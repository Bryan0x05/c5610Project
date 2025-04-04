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
PROMPT = "shell>"

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
        self.conID = 0
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
        if nickname in self.nicknames or nickname == 0:
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
        
    def sendConnIps( self, sock: socket.socket ):
        ''' Send a list of all ip addrs we are connected to'''
        peers: list[str] = [ ip for ( ip, _ ) in self.connections.keys() ]
        # S = sending, as in sending the info, R = requesting, requesting the info
        netProc.sendMsg( sock, messageHandler.encode_message(Command.GET_IPS, "S", *peers) )

    @ staticmethod
    def sendMsg( sock: socket.socket, msg : bytes ) -> bool:
        ''' Send a message through a socket corresponding to the nickname '''
        try:
            sock.sendall( msg )
            return True
        except Exception:
            # prints last exception and traceback to stderr
            logging.error( traceback.format_exc() )
            return False
    
    def shutDown( self ):
        ''' graceful shutdown '''
        for key, sock in self.connections.items():
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        exit(0)

            
class client(netProc):
    def __init__(self, port: int, sInfo: tuple[ str, int] ):
        super().__init__( port )
        self.sInfo = sInfo

    def getAllSocks( self, nickName : int) -> Union[ str, bool]:
        ''' Sends msg to server @ nickName to send all known sockets back'''
        try:
            return netProc.sendMsg( self.socket, messageHandler.encode_message( Command.GET_DICT, "0") )
        except TimeoutError:
            return "ERR: Timeout"
        except Exception:
            logging.error(traceback.format_exc())
            return False
    
    def listenLoop( self ):
        ''' Thread runs this function '''
        COM = 0
        ARG = 1
        msg = netProc.readMsg( self.socket )
        if msg is not None:
            logging.debug(f"Client read msg: {msg}")
            match msg[COM]:
                case Command.GET_DICT:
                    # print whole dictionary to stdout
                    print(msg[ARG][:])
                    print(PROMPT, end="", flush=True)
                    # update our local nickname dictionary
                    for argI in range(0, len(msg[ARG]) ):
                        # break up the key and value, and add them to our dictionary
                        eleList: list[str] = re.findall( "[0-9][.]?[0-9]?[.]?[0-9]?[.]?[0-9]?[.]?[0-9]?" ,msg[ARG][argI] )
                        # 0: sock nickname, 1: ipAddr,  2: port
                        self.nicknames[ int(eleList[0]) ] = ( eleList[1], int(eleList[2]) )
                    
                case default:
                    print("Client default case reached:")
                    pprint.pp(msg)
                    print( PROMPT, end="", flush=True )
            
        # TODO, use a reply scheme to figure out if client needs to take any action.
        # i.e. update their local dictionary
      
    def runLoop( self ):
        ''' Do all the client things '''
        # Connect to our local server process
        self.socket.connect( self.sInfo )
        # interactive console thread
        sh = shell(client=self)
        self.cmdThread = threadPlus( target = sh.cmdloop, name = "cmdThread" )

        # listen for server msgs and replies
        self.listenThread = threadPlus( target = self.listenLoop, name = "listenThread" )

        self.listenThread.start()
        self.cmdThread.start()
        
        self.cmdThread.join()
        self.listenThread.join()
        print( "Client is shutting down now!" )
        self.socket.close()
        exit( 0 )
            
class server(netProc):
    def __init__(self, port: int ):
        super().__init__( port )
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
        ''' Do all the server things '''
        COM = 0
        ARGS = 1
        # connect to our local client before anything else
        while not self.acceptConn():
            pass

        while( self.stop == False ):
            # NOTE: Assume the first argument is a socket

            msg = self.checkForMsgs()
            
            if msg is not None:
                logging.debug(f"Server read msg: {msg}")
                # TODO: Finish this logic
                match( msg[COM] ):
                    case Command.KILL_SERVER:
                        logging.debug("server shutting down")
                        # closes all server sockets on the way out
                        self.shutDown()
                    
                    case Command.KILL_NETWORK:
                        logging.debug("server killing network")
                        for _, sock in self.connections.items():
                            netProc.sendMsg( sock, messageHandler.encode_message( Command.KILL_NETWORK ) )
                        # close all our sockets
                        self.shutDown()

                    case Command.SEND_MSG:
                        nick = int( msg[ARGS][0] )
                        if not self.nicknameExists( nick ):
                            netProc.sendMsg( self.getSockByNickname( 0 ),
                                          messageHandler.encode_message(Command.SEND_MSG,"ERR: Recevier not in network!") )
                            continue
                        netProc.sendMsg( self.getSockByNickname( nick ), " ".join(msg[ARGS][1:]).encode() )

                    case Command.HEARTBEAT:
                        # Someone is asking us to send a heartbeat
                        if  msg[ARGS][0] == "R":
                            sock : socket.socket = self.getSockByNickname( int( msg[ARGS][0] ) )
                            netProc.sendMsg( sock, messageHandler.encode_message(Command.HEARTBEAT, "S", self.getMyIpAddr(), self.port) )
                        else: # S, someone is telling us their heartbeat
                            # print ipaddr, port
                            print(f"Heart from { msg[ ARGS ][ 1 ] }:{ msg[ ARGS ][ 2 ]}")
                            print( PROMPT, end="", flush = True )

                    case Command.GET_DICT:
                        sock : socket.socket =  self.getSockByNickname( int( msg[ ARGS ][ 0 ] ) )
                        netProc.sendMsg( sock, messageHandler.encode_message( Command.GET_DICT,
                            *[nick for nick in self.nicknames.items( )]) )
                    
                    case Command.KNOCK:
                        ipAddr =  msg[ ARGS ][ 0 ]
                        port =  int( msg[ ARGS ][ 1 ] )
                        print(f"knock args: {ipAddr}:{port}")
                        if self.connectToIp( ipAddr, port ):
                            print( "Connected to: {ipAddr}:{port}" )
                        else:
                            print( "ERR: Failed to connect to {ipAddr}:{port}" )
                        print( PROMPT, end="", flush= True )

                    case Command.GET_IPS:
                        # requesting us to give the list
                        if msg[ ARGS ][ 0 ] == "R":
                            self.sendConnIps( self.getSockByNickname( int( msg[ ARGS ][ 1 ]) ) )
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
                            print( PROMPT, end="", flush=True )

                    case default:
                        logging.debug("Server default case reached:")
                        pprint.pprint(msg)
                        print( PROMPT, end="", flush=True )

        print("Server shutting down now!")
        self.shutDown()

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
    prompt = PROMPT
    # TODO: Utilize messageHandler instead of directly sending byte coded strings
    def __init__(self, client : client, spin : bool = True ):
        super().__init__()
        self.client = client
        self.spin = spin
    
    def default( self, line ):
        '''Default behavior when command is not recongized'''
        print(f"ERR: {line} is an unrecongized command or an incomplete argument")
        
    def do_quit( self, _ ):
        '''exits the shell & terminates client'''
        # bring down listen thread on quit
        self.client.listenThread.stop()
        # set our thread to be brought down
        self.client.cmdThread.stop()
        # send msg to our local server
        self.client.socket.sendall( messageHandler.encode_message(Command.KILL_SERVER,"0") )
        print("Exiting...")
        return True
    
    def do_listSockets(self, line : str ):
        '''Polls server to return list of sockets <nickname: int | none>'''
        args = line.split()
        # if no arg provided, assume local server is the target
        if len(args) == 0: args.append( '0' )
        
        sockNickname = args[0]
        # assume they mean to ask local server
        if sockNickname == '': sockNick = 0
        else: sockNick = int( sockNickname )
        
        if not self.client.nicknameExists( sockNick ):
            print( f" ERR: Nickname {sockNick} is not an existing socket!")
        self.client.sendMsg( self.client.socket, messageHandler.encode_message(Command.GET_DICT,"0") )
        
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
        self.client.sendMsg( self.client.socket,messageHandler.encode_message(Command.KNOCK, ipAddr, port) )
    
    def do_sendMsg(self, line : str ):
        ''' <socketnickname: int> <msg: str>'''
        try:
            args = line.split()
            sockNick = int(args[0])
            msg = " ".join(args[1:])
        except:
            self.default( line )
            return
        
        if not self.client.nicknameExists( sockNick ):
            print( f" ERR: Nickname {sockNick} is not an existing socket!")
        # Sends msg to local server to forward this message to the corresponding socket
        self.client.sendMsg( self.client.socket, messageHandler.encode_message(Command.SEND_MSG, sockNick, msg) )

    def spinAnimation(self):
        if self.spin == False:
            return
        spinner = ['|', '/', '-', '\\']
        for symbol in spinner:
            print(f'\r{symbol} Waiting...', flush=True)
            time.sleep(0.1)

     
# script guard, things in this script don't run automatically when imported
if __name__ == "__main__":
    pass