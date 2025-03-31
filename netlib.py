from imaplib import Commands
import socket
import typing
import traceback
import logging
import cmd
import pprint
from typing import Union
import sys
import threading
from enum import Enum
import time
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

# might be excessive for what we're doing but the idea is we don't have to find debug prints later
# and remove them, we can just change the logging level.
logging.basicConfig(level=logging.DEBUG)

class threadPlus ( threading.Thread ):
    ''' Thread wrapper to externally killed in a safe manner'''
    def __init__(self, target, name, group = None, args=(),**kwargs ) -> None:
        super().__init__( group, target, name, args, kwargs, daemon=None )
        self.target = target
        self.args = args
        self.kwargs = kwargs
        self.stopFlag = threading.Event()
        
    def run( self ):
        ''' Run in a forver loop until stop flag is set'''
        print(" HEY I AM IN THE THREADPLUS RUN")
        while self.stopFlag:
            self.target( *self.args, **self.kwargs )
    
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
        self.socket.settimeout(5)
        self.stop = False

    def acceptConn( self ) -> bool:
        ''' Accept a socket connection, warning this is blocking by default'''
        # this is blocking! It'll wait until someone tries to talk to us!
        try:
            conSock, addrAndPort = self.socket.accept()
            logging.debug(f"Connected accepted on {addrAndPort}")
            self.nicknames[ self.conID ] = ( addrAndPort )
            self.conID += 1
            self.connections[ ( addrAndPort ) ] = conSock
            conSock.setblocking(False)
            conSock.settimeout(5)
            conSock.sendall( messageHandler.encode_message(Command.HEARTBEAT, "Socket alive on: ", *addrAndPort)  )
        except BlockingIOError:
            # logging.error( traceback.format_exc() ) # uncomment this at your own sanity
            return False
        except TimeoutError:
            logging.warning("timeout in accept connection")
            return False
        except Exception:
            logging.error( traceback.format_exc() )
            return False
        
        return True
        
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
            if nickname == 0:
                return self.socket
            
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
    
    def readMsg( self, sock : socket.socket ) -> Union[ tuple[ Command, list[ str ] ], None ]:
        ''' Read a socket message '''
        msg : bytes = bytes()
        incMsg : bytes = bytes()
        try:
            while len(incMsg := sock.recv(1024)) > 0:
                    msg += incMsg
        except TimeoutError: # Treating timeout as an async try again error
                # As a result, this will spam stdout.
                # logging.warning( traceback.format_exc() )
                pass
        # if someone shutdown the connection, bring yourself down
        except ConnectionResetError:
            logging.warning( traceback.format_exc() )
            self.stop = True
        except Exception:
                logging.error( traceback.format_exc() )
            
        if len(msg) > 0:
            logging.debug(f"Returning message: {msg}")
            return messageHandler.decode_message( msg )
        else:
            return None
        
    # TODO: Get connList may not work as intended, as it'll give the ipaddr + port
    # of servers sockets that are target to the specific node of the sender
    # instead, we should poll the network for the ipAddr and Port of their server
    # listening sockets.
    def sendConnList( self, sock: socket.socket ):
        ''' Send a list of all of our connections'''
        peers: list[str] = [ "{ip}:{port}" for ( ip, port ) in self.connections.keys() ]
        try:
            sock.send( ",".join(peers).encode() )
        except Exception:
            logging.error( traceback.format_exc() )
            exit(-1)

    def sendMsg( self, sock: socket.socket, msg : bytes ) -> bool:
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
            return self.sendMsg( self.socket, messageHandler.encode_message( Command.GET_DICT, "0") )
        except TimeoutError:
            return "ERR: Timeout"
        except Exception:
            logging.error(traceback.format_exc())
            return False
    
    def listenLoop( self ):
        ''' Thread runs this function '''
        time.sleep(10)
        print("I'M LISTENING")
        msg = self.readMsg( self.socket )
        print("After listen")
        if msg is not None:
            print(msg)
        time.sleep(10)
        # TODO, use a reply scheme to figure out if client needs to take any action.
        # i.e. update their local dictionary
      
    def runLoop( self ):
        ''' Do all the client things '''
        # Connect to our local server process
        self.socket.connect( self.sInfo )
        # interactive console thread
        sh = shell(client=self)
        self.cmdThread = threadPlus( target = sh.cmdloop, name = "cmdThread" )
        # TODO: Better processing logic for listenThread?
        # listen for server msgs and replies
        self.listenThread = threadPlus( target = self.listenLoop, name = "listenThread" )
        # TODO: GIL mutex is indeed a problem, and will not release the lock should listenthread get it
        # resulting in the command terminal thread being locked out effectively.
        # so um... we need to fix that...
        self.cmdThread.start()
        # NOTE: commented out listenthread for cmdline testing.
        # self.listenThread.start()
        
        self.cmdThread.join()
       #  self.listenThread.join()
        print( "Client is shutting down now!" )
        self.socket.close()
        exit( 0 )
            
class server(netProc):
    def __init__(self, port: int ):
        super().__init__( port )
        # listen to any IP, sending traffic to our port
        # assuming client and server both want to listen for now
        try:
            self.socket.bind( ( '', port ) )
            print(f"listening on port: {port}")
        except:
            logging.error( traceback.format_exc() )
            exit(-1)
        # OS should manage this queue, so its non-blocking
        self.socket.listen( 5 )

    def sendNicknames( self, socket : socket.socket ):
        ''' Send our copy of the nickname dictionary to the provided socket'''
        msg: bytes = messageHandler.encode_message(Command.GET_DICT, *[ nick for nick in self.nicknames.items() ] )
        if( not self.sendMsg( socket, msg ) ):
            print("EER: Failed to send Nickname dictionary")
        
    def runLoop( self ):
        ''' Do all the server things '''
        # connect to our local client before anything else
        while not self.acceptConn():
            pass
        
        while( self.stop == False ):
            COM = 0
            ARGS = 1

            # NOTE: assuming that a valid socket is the first argument a command has
            msg = self.readMsg( self.connections[ self.nicknames[0] ] )
            if msg is not None:
                logging.debug(f"Read msg: {msg}")
                match( msg[COM] ):
                    case Command.KILL_SERVER:
                        logging.debug("server shutting down")
                        # closes all server sockets on the way out
                        self.shutDown()
                    
                    case Command.KILL_NETWORK:
                        logging.debug("server killing network")
                        # TODO: Broadcast the killnetwork message, likley with a broadcast function
                        # close all our sockets
                        self.shutDown()

                    case Command.SEND_MSG:
                        nick = int( msg[ARGS][0] )
                        continue # DEV: code is not built to handle server replies to client yet.
                        if not self.nicknameExists( nick ):
                            self.sendMsg( self.getSockByNickname( 0 ), "ERR: Nickname doesn't exist " )
                            continue      
                        sock : socket.socket = self.getSockByNickname( nick )
                        self.sendMsg( sock, " ".join(msg[ARGS][1:]).encode() )

                    case Command.HEARTBEAT:
                        if int( msg[ARGS][0] ) > -1:
                            sock : socket.socket = self.getSockByNickname( int( msg[ARGS][0] ) )
                            # putting -1, means I'm not providing a valid socket for the receiver to reply to.
                            # i.e. do not reply to my reply of your heartbeat message.
                            continue # Code not ready for real topology stuff
                            self.sendMsg( sock, messageHandler.encode_message(Command.HEARTBEAT, "-1") )
                               
                    case default:
                        pprint.pprint(msg)
                    
            # NOTE: Logic needed
            # 1. Recongize kill command, by setting self.stop
            # 2. Any external messaging commands
            # 3. All the other commands like knock, get_dict, etc.
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
        
        return (str(len(contents)) + ":" + contents).encode()
    
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
    # TODO: Utilize messageHandler instead of directly sending byte coded strings
    def __init__(self, client : client ):
        super().__init__()
        self.client = client
    
    def default( self, line ):
        '''Default behavior when command is not recongized'''
        print(f"ERR: {line} is an unrecongized command or an incomplete argument")
        
    def do_quit(self, line):
        '''exits the shell & terminates client'''
        # bring down listen thread on quit
        self.client.listenThread.stop()
        # set our thread to be brought down
        self.client.cmdThread.stop()
        # send msg to our local server
        self.client.socket.sendall( messageHandler.encode_message(Command.KILL_SERVER,"0") )
        print("Exiting...")
        exit(0)
    
    def do_listSockets(self, line : str ):
        '''Polls server to return list of sockets <nickname: int | none>'''
        args = line.split()
        sockNickname = args[0]
        # assume they mean to ask local server
        if sockNickname == '': sockNick = 0
        else: sockNick = int( sockNickname )
        
        if not self.client.nicknameExists( sockNick ):
            print( f" ERR: Nickname {sockNick} is not an existing socket!")
        # NOTE: Currently, no support for chained commands like getting a dict from a non-local server
        # NOTE: Also need a reply scheme, since replies may come in different order then expected
        self.client.socket.sendall( messageHandler.encode_message(Command.GET_DICT,"0") )
       
    def do_makeConnection(self, line: str):
        ''' Connect to a given ipaddress or host'''
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
     
# script guard, things in this script don't run automatically when imported
if __name__ == "__main__":
    pass