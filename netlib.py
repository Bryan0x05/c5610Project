from imaplib import Commands
import socket
import typing
import traceback
import logging
import cmd
import pprint
from typing import Union
import re
import threading
from enum import Enum
import time
import sys
# import colorama # for different colored text to help tell apart certain messages
# import curses # linux based module for terminal formatting

# argument seperator
ASEP = "|"

class Command(Enum):
    GET_DICT = 0     # Client -> Server: Get nickname dictionary from server
    SEND_MSG = 1     # Client -> Server: Send a message to someone else in the network
    RECV_MSG = 2     # Server -> Client: A message has arrived for the client - pass it on
    KNOCK = 3        # Knock
    HEARTBEAT = 4    # Heartbeat
    KILL_SERVER = 5  # Client -> Server: Kill the server process
    KILL_NETWORK = 6 # Client -> Server, Server -> Server: Kill the entire network by sending the message to all other nodes
    GET_IPS = 7
# might be excessive for what we're doing but the idea is we don't have to find debug prints later
# and remove them, we can just change the logging level.
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
    def __init__( self, port: int):
        self.port = port
        # 0 means the client/server socket in our node
        self.conID = 1
        self.connections: typing.Dict[ tuple [ str, int ], socket.socket] = {}
        self.nicknames: typing.Dict[ int, tuple[ str, int ] ] = {}
        # ipv4, TCP
        self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.socket.setblocking(False)
        self.socket.settimeout(2)
        self.stop = False

    def acceptConn( self ) -> bool:
        ''' Accept a socket connection, warning this is blocking by default'''
        # this is blocking! It'll wait until someone tries to talk to us!
        try:
            conSock, addrAndPort = self.socket.accept()
            logging.debug(f"Connected accepted on {addrAndPort}, nickname: {self.conID}")
            self.nicknames[ self.conID ] = ( addrAndPort )
            self.conID += 1
            self.connections[ ( addrAndPort ) ] = conSock
            conSock.setblocking(False)
            conSock.settimeout(2)
            # S = sending a heartbeat, R = requesting a heartbeat
            conSock.sendall( messageHandler.encode_message(Command.HEARTBEAT, "S", *addrAndPort)  )
            return True
        except BlockingIOError:
            # logging.error( traceback.format_exc() ) # uncomment this at your own sanity
            return False
        except TimeoutError:
            logging.warning("timeout in accept connection")
            return False
        except Exception:
            logging.error( traceback.format_exc() )
            return False
        
    def connectToHost( self, hostName: str, port: int ) -> bool:
       ''' Connects by host name e.g. www.google.com '''
       return self.connectToIp( socket.gethostbyname( hostName ), port )
    
    def connectToIp( self, ipAddr: str, port : int ) -> bool:
        ''' Connects by ipv4 address '''
        sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        try:
            if ( ipAddr, port ) in self.connections:
                logging.debug(f"Already connected to {ipAddr}:{port}" )
            else:
                sock.connect( (ipAddr, port) )
                # only store on a success connection
                self.connections[ ( ipAddr, port ) ] = sock
                self.nicknames[self.conID ] = ( ipAddr, port )
                logging.debug(f" Connected to {ipAddr}:{port}, connection nickname: {self.conID} ")
                self.conID += 1
            return True
        # using Exception to exclude base exceptions like SystemExit or keyboardinterrupt
        except Exception:
            # prints last exception and traceback to stderr
            logging.error( traceback.format_exc() )
            return False
    
    def getMyIpAddr( self ) -> str:
        '''...gets my own ip address'''
        return socket.gethostbyname( socket.gethostname() )
    
    def getSockByNickname( self, nickname: int ) -> socket.socket:
        ''' Returns the socket object associated with the nickname'''
        try:
            return self.connections[ self.nicknames[ nickname ] ]
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
        for idx, key in enumerate( self.nicknames ):
            print("{idx}. {key} => {self.nicknames[key]} ") 
    
    @staticmethod
    def readMsg( sock : socket.socket ) -> Union[ tuple[ Command, list[ str ] ], None ]:
        ''' Read a socket message '''
        msg : bytes = bytes()
        incMsg : bytes = bytes()
        try:
            while len( incMsg := sock.recv(1024) ) > 0:
                    msg += incMsg
        except TimeoutError: # Treating timeout as an async try again error
                # As a result, this will spam stdout.
                # logging.warning( traceback.format_exc() )
                pass
        except ConnectionResetError:
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
        peers: list[str] = [ ip for ( ip, _ ) in self.connections.keys() ]
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
        for key, sock in self.connections.items():
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        exit(0)

class peer(netProc):
    def __init__(self, port: int, input = None, output = None ):
        super().__init__( port )
        if input is not None:
            sys.stdin = input
        
        if output is not None:
            sys.stdout = output
        # listen to any IP, sending traffic to our port
        # assuming client and server both want to listen for now
        try:
            # Allow socket re-use to get around linux wait state
            # basically lets you spam run the script without changing the port numbers in Linux.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind( ( '', port ) )
            print(f"listening on port: {port}")
        except:
            logging.error( traceback.format_exc() )
            exit(-1)
        # OS should manage this queue, so its non-blocking
        self.socket.listen( 5 )
    
    def checkForMsgs( self ):
        ''' Check for a message from all our sockets, returning the first one found'''
        for _, sock in self.connections.items():
            msg = netProc.readMsg( sock )
            if msg is not None:
                return msg
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
        self.socket.close()
        exit( 0 )
    
    def listenLoop( self ):
        ''' Do all the server/client things '''
        COM = 0
        ARGS = 1
        
        # NOTE: Assume the first argument is a socket
        msg = self.checkForMsgs()
        
        if msg is not None:
            logging.debug(f"Server read msg: {msg}")
            # TODO: Finish this logic
            match( msg[COM] ):
                case Command.KILL_SERVER:
                    self.kill_peer()
                
                case Command.KILL_NETWORK:
                    self.kill_network()

                case Command.SEND_MSG:
                    nick = int( msg[ARGS][0] )
                    self.sendMsg( nick, messageHandler.encode_message(Command.RECV_MSG, " ".join(msg[ARGS][1:]) ))
                
        
                case Command.RECV_MSG:
                    msg = msg[ARGS][0]
                    print( msg )
                    
                case Command.HEARTBEAT:
                    # Someone is asking us to send a heartbeat
                    if  msg[ARGS][0] == "R":
                        self.heartbeat_request(int( msg[ARGS][0] ))
                    else: # S, someone is telling us their heartbeat
                        # print ipaddr, port
                        print(f"Heart from { msg[ ARGS ][ 1 ] }:{ msg[ ARGS ][ 2 ]}")
                
                case Command.KNOCK:
                    self.knock(msg[ ARGS ][ 0 ], int( msg[ ARGS ][ 1 ] ))  

                case Command.GET_IPS:
                    # requesting us to give the list
                    if msg[ ARGS ][ 0 ] == "R":
                        self.sendConnIps( int( msg[ ARGS ][ 1 ]) )
                    # sending us a list
                    if msg[ ARGS ][ 0 ] == "S":
                        ips = msg[ ARGS ][ 1: ]
                        # NOTE: Might want to chance this, but for now auto-connect to those ips
                        keys = self.connections.keys()
                        ipAddrs = [ key[0] for key in keys ]
                        for ip in ips:
                            if  ip not in ipAddrs:
                                # NOTE: Might want to use a different port? and/or retry on failure?
                                if self.connectToIp( ip, self.port ):
                                    print(f"Connection made to: {ip}:{self.port}")
                                else:
                                    print(f"ERR: Failed to connect to: {ip}:{self.port}")

                case default:
                    logging.debug("Server default case reached:")
                    pprint.pprint(msg)

        # print("Server shutting down now!")
        # self.shutDown()
        
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
        return self.sendMsg(nickname, messageHandler.encode_message(Command.HEARTBEAT, "S", self.getMyIpAddr(), self.port) )
         

    def knock(self, ip_addr, port) -> bool:
        print(f"knock args: {ip_addr}:{port}")
        if self.connectToIp( ip_addr, port ):
            print( f"Connected to: {ip_addr}:{port}" )
            return True
        else:
            print( f"ERR: Failed to connect to {ip_addr}:{port}" )
            return False

class messageHandler():
    # TODO: write functions
    #  1. message cats:
    #     1.1. Commands for the server to do
    #     1.2. Msgs for the server to pass on
    # commands / msgs:
    #  1. Get nickname dictionary form server
    #  2. sendmsg
    #  3. knock
    #  4. heartbeat
    #  5. recvmsg
    #  6. shutdown server
    #  7. Shutdown whole network command (DEV)
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
    def decode_message( message: bytes) -> tuple [Command, list ]:
        '''Turn the encoded format [length of command + data]:[command][data] into (command, data); Also checks the length'''
        m: str = message.decode()
        length: int = int(m.split(":", 1)[0])
        m = m.split(":", 1)[1]
        if len(m) != length:
            raise RuntimeError("Length of received message doesn't match expected length!")
        comm = Command(int(m[0]))
        args = m[1:].split(ASEP)
        return comm, args

# This might be a 3rd process, or its part of the client process. If that's the case
# maybe all socket communcation should be done through the server process, so we ensure nothing
# on the client is blocking? I think the server part maybe should handle itself
# and the user only interacts with the client portion?
class shell(cmd.Cmd):
    intro = "Type help to get started\n"
    prompt = "shell>"
    def __init__(self, peer : peer, spin : bool = True ):
        super().__init__()
        self.peer = peer
        self.spin = spin
    
    def default( self, line ):
        '''Default behavior when command is not recongized'''
        print(f"ERR: {line} is an unrecongized command or an incomplete argument")
        
    def do_quit( self, _ ):
        '''exits the shell & terminates client'''
        return True
    
    def do_listSockets(self, _ ):
        '''Return the list of sockets '''
        pprint.pprint(self.peer.nicknames)
        
    def do_makeConn(self, line: str):
        ''' Connect to a given < ipAddr(x.x.x.x) > < port >'''
        try:
            args = line.split()
            ipAddr = args[0]
            port = args[1]
        except:
            self.default(line)
            return
        # Sends msg to local server to forward this message to the corresponding socket
        self.peer.knock(ipAddr, port)
    
    def do_sendMsg(self, line : str ):
        ''' <socketnickname: int> <msg: str>'''
        try:
            args = line.split()
            sockNick = int(args[0])
            msg = " ".join(args[1:])
        except:
            self.default( line )
            return
        
        if not self.peer.nicknameExists( sockNick ):
            print( f" ERR: Nickname {sockNick} is not an existing socket!")
        # Sends msg to local server to forward this message to the corresponding socket
        self.peer.sendMsg( sockNick, messageHandler.encode_message(Command.SEND_MSG, msg) )
    
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