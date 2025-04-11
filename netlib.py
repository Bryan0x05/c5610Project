from imaplib import Commands
import socket
import typing
import traceback
import logging
import cmd
import pprint
from typing import Union, Tuple, List
import threading
from enum import Enum
import time
import os
import subprocess
import pty
import colorama
# import curses # linux based module for terminal formatting

# argument seperator
ASEP = "|"

class Command(Enum):
    GET_DICT = 0     # Node <-> Node: Get nickname dictionary from Node
    SEND_MSG = 1     # Node <-> Node: Send a message to someone else in the network
    RECV_MSG = 2     # Node <-> Node: A message has arrived for the client - pass it on
    KNOCK = 3        # Node <-> Node: Connect to network, handshake
    HEARTBEAT = 4    # Node <-> Node: Heartbeat, I'm alive!
    KILL_SERVER = 5  # Node <-> Node: Kill the peer process
    KILL_NETWORK = 6 # Node <-> Node: Kill the entire network by sending the message to all other nodes
    GET_IPS = 7      # Node <-> Node: Give me all the ip addresses you are connected too.


logging.basicConfig(level=logging.DEBUG)

class threadPlus ( threading.Thread ):
    ''' Thread wrapper to externally killed in a safe manner'''
    def __init__(self, *args, **kwargs) -> None:
        super( threadPlus, self ).__init__(*args, **kwargs)
        self.stopFlag = threading.Event()
        
    def run( self ):
        ''' Run in a forver loop until stop flag is set'''
        while not self.stopFlag.isSet():
            # NOTE: VSC can't see it, but parent class variables are in scope. So we're just gonna ignore the error
            self._target( *self._args, **self._kwargs ) # type: ignore
        
    def stop(self):
        ''' Set stop flag '''
        self.stopFlag.set()
        
class netProc:
    '''Super class for the common networking functions between client and server'''
    IN = 0
    OUT = 1
    def __init__( self, port: int):
        self.port = port
        # 0 means the client/server socket in our node
        self.conID = 1
        self.outboundConns: typing.Dict[ Tuple [ str, int ], socket.socket] = {}
        self.inboundConns: typing.Dict[ Tuple [ str, int ], socket.socket] = {}
        # keyed by int, with a 2-tuple of 2tuples each holding str,int pair
        self.nicknames: typing.Dict[ int, Tuple[ Tuple[str, int], Tuple[str, int] ] ] = {}
        # ipv4, TCP
        self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.socket.setblocking(False)
        self.stop = False
        self.proc = None
    
    @staticmethod
    def getPort( sock : socket.socket ) -> int:
        ''' get's a socket port number'''
        return sock.getsockname()[1]
    
    @staticmethod
    def getIp( sock : socket.socket ) -> str:
        '''Gets a socket's ip address'''
        return sock.getsockname()[0]
    @staticmethod
    def getLanIp() -> str:
        try:
            # sacrificial socket to find the lan ip without usual requirements
            s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM)
            # connect to google DNS on HTTP port
            s.connect( ("8.8.8.8", 80) )
            # get the ip
            ip = str( s.getsockname()[0] )
            s.close()
            return ip
        except Exception:
            logging.warning("Err, unable to resolve lan ip!")
            logging.error( traceback.format_exc )
            # return loopback intf for our local machine
            # NOTE: This means we are unable to connect outside of our own machine
            return "127.0.0.1" 
        
    def completeHandshake( self, inSock : socket.socket, conID : int, ip : str , port : int ) -> bool:
        ''''Accepts Step 3 of the handshake reply, terminates handshake'''
        ARG = 1
        print("in complete handshake")
        try:
            if not self.nicknameExists( conID ):
                logging.error( traceback.format_exc() )
                return False
            
            self.outboundConns[ ip, port] = inSock
            outSockInfo = self.nicknames[conID][self.IN]
            self.nicknames[ conID ] = ( (outSockInfo), (ip, port) )
        except BlockingIOError:
            # logging.error( traceback.format_exc() ) # uncomment this at your own sanity
            return False
        except TimeoutError:
            # logging.warning("timeout in accept connection")
            return False
        except Exception:
            logging.error( traceback.format_exc() )
            return False
        return True

            
    def acceptConn( self ) -> bool:
        ''' Accept a socket connection, warning this is blocking by default'''
        ARGS = 1
        msg = None
        try:
            # Despite accepting this connection the other peer actually doesn't know to listen to this port so its only 1-way.
            inSock, addrAndPort = self.socket.accept()
            inSock.settimeout(3)
            logging.debug(f"Accept connection on {addrAndPort}, nickname: {self.conID}")
            print(colorama.Fore.GREEN, "Accepted connection, handshake in progress..." + colorama.Style.RESET_ALL)
            # TODO, add a timeout
            msg = netProc.readMsg( inSock )
            
            self.inboundConns[ ( addrAndPort ) ]  = inSock
            
            if msg is None:
                logging.error( "bad things are happening")
                return False
            # step 3
            if msg[ARGS][0] == 'R':
                print("HEY, we got the R-flag Knock")
                self.inboundConns[ addrAndPort ] = inSock
                self.nicknames[ int(msg[ARGS][1]) ] = ( addrAndPort, tuple() ) 
                return self.completeHandshake( inSock, int(msg[ARGS][1]), *(inSock.getpeername()) )
            
            # Get handshake information ( step 2)
            replyIp = str( addrAndPort[0] )
            replyId = int ( msg[ARGS][0] )
            replyPort = int( msg[ARGS][1] )
            
            outSock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            outSock.setblocking(False)
            # Make an out-bound connect to the port the other peer knows to listen to
            outSock.connect( ( replyIp, replyPort ) )
            print(colorama.Fore.GREEN, "Handshake in progress[step2 complete]..." + colorama.Style.RESET_ALL)

            # Inform that peer we are part of the handshake associated with replyID, R=> replying
            outSock.sendall( messageHandler.encode_message( Command.KNOCK, 'R', replyId ) )
            self.outboundConns[ ( replyIp, replyPort ) ] = outSock
            self.nicknames[ self.conID ] =  ( (addrAndPort), (replyIp, replyPort ) )
            self.conID += 1
            return True
        except BlockingIOError:
            # logging.error( traceback.format_exc() ) # uncomment this at your own sanity
            return False
        except TimeoutError:
            # logging.warning("timeout in accept connection")
            return False
        except Exception:
            logging.error( traceback.format_exc() )
            return False
    
    def closeConn( self, nickname : int ):
        sock : socket.socket = self.getSockByNickname( nickname )
        # TODO: Replace this with a message / command to let the other server know to also clean
        # up the connection their end and update their dictionary.
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        self.inboundConns.pop( self.nicknames[nickname][self.IN])
        self.outboundConns.pop( self.nicknames[nickname][self.OUT] )
        self.nicknames.pop( nickname )
        
    def connectToHost( self, hostName: str, port: int ) -> bool:
       ''' Connects by host name e.g. www.google.com '''
       return self.connectToIp( socket.gethostbyname( hostName ), port )
    
    def connectToIp( self, ipAddr: str, port : int ) -> bool:
        ''' Connects by ipv4 address '''
        sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        try:
            if ( ipAddr, port ) in self.outboundConns:
                logging.debug(f"Already connected to {ipAddr}:{port}" )
            else:
                sock.connect( (ipAddr, port) )
                # step 1 of the handshake
                sock.sendall( messageHandler.encode_message(Command.KNOCK, self.conID, self.port ) )
                self.outboundConns[ ( ipAddr, port ) ] = sock
                self.nicknames[self.conID ] = ( tuple(), ( ipAddr, port ) )
                self.conID += 1
                logging.debug(f" Connected to {ipAddr}:{port}, connection nickname: {self.conID} ")
            return True
        # using Exception to exclude base exceptions like SystemExit or keyboardinterrupt
        except Exception:
            # prints last exception and traceback to stderr
            logging.error( traceback.format_exc() )
            return False
    
    def getSockByNickname( self, nickname: int ) -> socket.socket:
        ''' Returns the socket object associated with the nickname'''
        try:
            return self.outboundConns[ self.nicknames[ nickname ][self.OUT] ]
        except Exception:
            logging.error( traceback.format_exc() )
            # NOTE: We exit here, because certain code expects this function
            # to always return a socket. See "nicknameExists" to santiy check.
            exit(-1)
        
    def nicknameExists( self, nickname: int ):
        '''' Checks if corresponding nickname exists '''
        # this function exists since geSockByNickname needs to always
        # return a sock instead of  a sock or bool
        
        # 0 meaning to contact our local server
        if nickname in self.nicknames:
            return True
        return False

    def listAllConns( self ):
        ''' List all socket connections in <nickname> => <ip>:<port> format'''
        conns = []
        for idx, key in enumerate( self.nicknames ):
            conns.append( f"{idx}. {key} => {self.nicknames[key]}" )
        return conns
    
    @staticmethod
    def readMsg( sock : socket.socket ) -> Union[Tuple[Command, List[str]], None]:
        ''' Read a socket message '''
        msg : bytes = bytes()
        incMsg : bytes = bytes()
        try: # TODO: Process and only read up to header size instead of reading forever until we timeout
            while len( incMsg := sock.recv(1024) ) > 0:
                    msg += incMsg
        except ( socket.timeout, BlockingIOError ): # Treating timeout as an async try again error
            pass
        except OSError:
            logging.warning( traceback.format_exc() )
        except Exception:
            logging.error( traceback.format_exc() )
            
        if len(msg) > 0:
            # logging.debug(f"Returning message: {msg}")
            return messageHandler.decode_message( msg )
        else:
            return None
        
    def sendConnIps( self, nickname: int ):
        ''' Send a list of all ip addrs we are connected to'''
        peers: list[str] = [ ip for ( ip, _ ) in self.outboundConns.keys() ]
        # S = sending, as in sending the info, R = requesting, requesting the info
        self.sendMsg( nickname, messageHandler.encode_message(Command.GET_IPS, "S", *peers) )

    def sendMsg( self, nickname: int, msg : bytes ) -> bool:
        ''' Send a message through a socket corresponding to the nickname '''
        if self.nicknameExists( nickname ):
            try:
                self.getSockByNickname(nickname).sendall( msg )
                return True
            except Exception:
                # prints last exception and traceback to stderr
                logging.error( traceback.format_exc() )
                return False
        else:
            logging.error(f"Cannot send a message to {nickname} - not found in connection dict!")
            return False
    
    def shutDown( self ):
        ''' graceful shutdown '''
        for key, sock in self.outboundConns.items():
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        self.socket.close()
        exit(0)

class peer(netProc):
    def __init__(self, port: int = 0, name: str = "_", subProc = False, debug = False, test = False ):
        super().__init__( port )
        self.name = name
        self.port = port
        self.ip = "No ip"
        self.subProc = subProc
        self.test = test
        ( logging.getLogger() ).disabled = not debug
    
    def checkForMsgs( self ):
        ''' Check for a message from all our sockets, returning the first one found'''
        # unitTests seem to getting stuck in the floor when self.connections is empty
        for _, sock in self.inboundConns.items():
            msg = netProc.readMsg( sock )
            if msg is not None:
                return (msg, sock)
        return None

    def runLoop( self ):
        ''' Do all the client things '''
        # interactive console thread
        sh = shell(peer=self)
        self.cmdThread = threadPlus( target = sh.cmdloop, name = "cmdThread" )

        # listen for msgs and replies
        self.listenThread = threadPlus( target = self.listenLoop, name = "listenThread" )

        self.listenThread.start()
        self.cmdThread.start()
        
        self.cmdThread.join()
        self.listenThread.join()
        print( "Peer is shutting down now!" )
        self.up = False
        self.shutDown()

    def listenLoop( self ):
        ''' Do all the server/client things '''
        COM = 0
        ARGS = 1
        
        # see if there are any new connections
        self.acceptConn()
        # see if there are any new messages on existing connections
        readMsg: Union[Tuple[Tuple[Command, List[str]], socket.socket], None] = self.checkForMsgs()
        
        if readMsg is not None:
            revSock = readMsg[1]
            msg: Union[Tuple[Command, List[str]], None] = readMsg[0]
            logging.debug(f"Server read msg: {msg}")
            if msg[COM] == Command.KILL_SERVER:
                self.kill_peer()
            elif msg[COM] == Command.KILL_NETWORK:
                self.kill_network()
            elif msg[COM] == Command.SEND_MSG:
                nick = int( msg[ARGS][0] )
                
                self.sendMsg( nick, messageHandler.encode_message(Command.RECV_MSG, " ".join(msg[ARGS][1:]) ))
            elif msg[COM] == Command.RECV_MSG:
                msgRecv = msg[ARGS][1:]
                print(colorama.Fore.BLUE,f"From: {msg[ARGS][0]}, msg: {msgRecv}" + colorama.Style.RESET_ALL )
            elif msg[COM] == Command.HEARTBEAT:
                # Someone is asking us to send a heartbeat
                if msg[ARGS][0] == "R":
                    self.heartbeat_request(int( msg[ARGS][0] ))
                else: # S, someone is telling us their heartbeat
                    # print ipaddr, port
                    print(f"Heart from { msg[ ARGS ][ 1 ] }:{ msg[ ARGS ][ 2 ]}")
            elif msg[COM] == Command.KNOCK:
                # step 3
                if msg[ARGS][0] == 'R':
                    print(colorama.Fore.GREEN, "Handshake in progress[step3.1]..." + colorama.Style.RESET_ALL)
                    self.completeHandshake( revSock, int( msg[ARGS][1] ), *(revSock.getpeername()) )
                    print(colorama.Fore.GREEN, "Handshake done!" + colorama.Style.RESET_ALL)

                else: # step 2 is handled in accept conn, not here.
                    pass
            elif msg[COM] == Command.GET_IPS:
                # requesting us to give the list
                if msg[ ARGS ][ 0 ] == "R":
                    self.sendConnIps( int( msg[ ARGS ][ 1 ]) )
                # sending us a list
                if msg[ ARGS ][ 0 ] == "S":
                    ips = msg[ ARGS ][ 1: ]
                    # NOTE: Might want to chance this, but for now auto-connect to those ips
                    keys = self.outboundConns.keys()
                    ipAddrs = [ key[0] for key in keys ]
                    for ip in ips:
                        if  ip not in ipAddrs:
                            # NOTE: Might want to use a different port? and/or retry on failure?
                            if self.connectToIp( ip, self.port ):
                                print(f"Connection made to: {ip}:{self.port}")
                            else:
                                print(colorama.Fore.RED, f"ERR: Failed to connect to: {ip}:{self.port}" + colorama.Style.RESET_ALL)
            else:
                logging.debug("Peer default case reached:")
                pprint.pprint(msg)
        
    def kill_peer(self) -> bool:
        logging.debug("peer shutting down")
        # closes all server sockets on the way out
        self.shutDown()
        return True
    
    def kill_network(self) -> bool:
        logging.debug("server killing network")
        for nick, _ in self.nicknames.items():
            self.sendMsg( nick, messageHandler.encode_message( Command.KILL_NETWORK ) )
        # close all our sockets
        self.shutDown()
        return True
        
    def heartbeat_request(self, nickname) -> bool:
        return self.sendMsg(nickname, messageHandler.encode_message(Command.HEARTBEAT, "S", self.ip, self.port) )
         
    def knock(self, ip_addr, port) -> bool:
        if self.connectToIp( ip_addr, port ):
            print(colorama.Fore.GREEN, f"Connected to {ip_addr}:{port}" + colorama.Style.RESET_ALL )
            return True
        else:
            print( colorama.Fore.RED, f"ERR: Failed to connect to {ip_addr}:{port}" + colorama.Style.RESET_ALL )
            return False

    def start( self ) :
        ''' Bind the socket and start the peer '''
        self.up = True
        try:
            # Allow socket re-use to get around linux wait state
            # basically lets you spam run the script without changing the port numbers in Linux.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind( ( netProc.getLanIp() , self.port ) )
            # if port = 0, the OS picks one for us, and we find out what it is here.
            self.port = netProc.getPort( self.socket )
            self.ip = self.getIp( self.socket )
            logging.debug(f"{self.name} socket up on: {self.ip}:{self.port}")
        except:
            logging.error( traceback.format_exc() )
            exit(-1)
        
        # OS should manage this queue, so its non-blocking
        self.socket.listen( 5 )
        # don't do anything in an interactive function if this is a test
        if self.test:
            return
        
        # Sets up subProc if true
        if self.subProc == True:
            # mfd, sfd are file descriptprs created from pty.openpty() in which case they shuold be ints.
            self.masterFd, self.servantFd = pty.openpty()
            command = [ "python3", "setupNode.py", self.ip, str( self.port ) ]
            self.proc = subprocess.Popen(
                command, stdin=self.masterFd, # stdout = subprocess.PIPE, 
                stderr = subprocess.PIPE, text = True )
        else:
            self.runLoop()

    # ======= BELOW ARE SUB PROC FUNCTIONS ===========
    def sendCommand( self, command : str ):
        ''' Sends a command through the redirected stdin'''
        if self.proc == None:
            raise ValueError("ERR: Trying to sendCommand to subprocess when none exists!")
        # send command
        os.write( self.masterFd, (command+"\n").encode() )
    
    def readProc( self ):
        ''' Read output from subprocess '''
        return # DEBUG: DO NOT LEAVE THIS HERE.
        if self.proc == None:
            raise ValueError("ERR: Trying to readProc from subprocess when none exists!")
        return self.proc.stdout.readline() # type: ignore
        
    def getAttr( self, attrName ):
        try:
            return getattr(self, attrName )
        except AttributeError:
            logging.error(f"Attribute '{attrName}' not found in the object.")
        
class messageHandler():

    def __init__(self):
        pass
    
    @staticmethod
    def encode_message( command: Command, *args ) -> bytes:
        '''Turn a command and data into the encoded format [length of command + data]:[command][data1|data2]'''
        # Might need standard format for seperating arguments in the data field.
        contents: str = str(command.value)
  
        for idx, arg in enumerate(args):
            contents += str( arg )
            if idx < len(args) - 1:
                contents += ASEP
        
        return ( str ( len ( contents ) ) + ":" + contents ).encode()
    
    @staticmethod
    def decode_message( message: bytes) -> Tuple[Command, list]:
        '''Turn the encoded format [length of command + data]:[command][data] into (command, data); Also checks the length'''
        m: str = message.decode()
        length: int = int(m.split(":", 1)[0])
        m = m.split(":", 1)[1]
        if len(m) != length:
            raise RuntimeError("Length of received message doesn't match expected length!")
        comm = Command(int(m[0]))
        args = m[1:].split(ASEP)
        return comm, args

class shell(cmd.Cmd):
    intro = "Type help to get started\n"
   
    prompt = "shell>"
    def __init__(self, peer : peer, spin : bool = True ):
        super().__init__()
        self.peer = peer
        self.spin = spin
    
    def default( self, line ):
        '''Default behavior when command is not recongized'''
        print( colorama.Fore.RED, f"ERR: {line} is an unrecongized command or an incomplete argument" + colorama.Style.RESET_ALL)
    
    def do_clear( self, _):
        ''' Clear screen '''
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def do_name( self, _ ):
        ''' prints the name of our peer'''
        print( self.peer.name )
        
    def do_quit( self, _ ):
        '''exits the shell & terminates client'''
        self.peer.up = False
        return True
    
    def do_listSockets(self, _ ):
        '''Return the list of sockets '''
        pprint.pprint(self.peer.nicknames)
        
    def do_makeConn(self, line: str):
        ''' Connect to a given < ipAddr(x.x.x.x) > < port >'''
        try:
            args = line.split()
            ipAddr = args[0]
            port = int( args[1] )
        except:
            self.default(line)
            return
        # Sends msg to local server to forward this message to the corresponding socket
        self.peer.knock( ipAddr, port)
    
    def do_sendMsg(self, line : str ):
        ''' <socketnickname: int> <msg: str>'''
        try:
            args = line.split()
            sockNick = int(args[0])
            msgSrc = self.peer.ip
            msg = " ".join(args[1:])
        except:
            self.default( line )
            return
        if self.peer.nicknameExists( sockNick ):
            if not self.peer.sendMsg( sockNick, messageHandler.encode_message(Command.RECV_MSG, msgSrc, msg) ):
                print(colorama.Fore.RED, f"ERR: Sending message to {sockNick} failed!" + colorama.Style.RESET_ALL)
            else:
                print(colorama.Fore.GREEN, "Message sent!" + colorama.Style.RESET_ALL)
        else:
            print(colorama.Fore.RED, f" ERR: Nickname {sockNick} is not an existing socket!" + colorama.Style.RESET_ALL )  
                
    def do_myInfo( self, _ ):
        ''' myInfo <none>, prints ip:port of our peer'''
        print(colorama.Fore.GREEN,f"{self.peer.ip}:{self.peer.port}" + colorama.Style.RESET_ALL)
    
    def do_getAttr( self, line ):
        try:
            args = line.split()
            name = args[0]
            print( self.peer.getAttr( name ) )
        except:
            self.default(line)

    def spinAnimation(self):
        if self.spin == False:
            return
        spinner = ['|', '/', '-', '\\']
        for symbol in spinner:
            print( f'\r{symbol} Waiting...', end="", flush=True )
            time.sleep(0.1)

    def postcmd(self, stop, line):
        if stop:
            # bring down listen thread on quit
            self.peer.listenThread.stop()
            # set our thread to be brought down
            self.peer.cmdThread.stop()
            time.sleep(1)
            # send msg to our local server
            print("Exiting...")
        return stop
        
# script guard, things in this script don't run automatically when imported
if __name__ == "__main__":
    pass
