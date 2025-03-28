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
# import colorama # for different colored text to help tell apart certain messages
# import curses # weird name, it allows us to do some formatting the cmd.cmd terminal. 
# for insance we want incoming messages to be in a different area on the terminal screen.
# Though its a linux-based module

# might be excessive for what we're doing but the idea is we don't have to find debug prints later
# and remove them, we can just change the logging level.
logging.basicConfig(level=logging.DEBUG)

class threadPlus(threading.Thread):
    ''' Wrapper to a thread to be externally killed in a safe manner'''
    def __init__( self, func, *args, **kwargs ):
        '''' Initialize thread with func and args'''
        super().__init__()
        self.func = func
        self.args = args
        self.kwards = kwargs
        self.stopFlag = threading.Event()
    
    def run( self ):
        ''' Run in a forver loop until stop flag is set'''
        while not self.stop:
            self.func(*self.args, **self.kwards)
    
    def stop(self):
        ''' Set stop flag '''
        self.stopFlag.set()
        
class netProc:
    '''Super class for the common networking functions between client and server'''
    def __init__( self, port: int):
        self.port = port
        self.conID = 1
        self.connections: typing.Dict[ tuple [ str, int ], socket.socket] = {}
        self.nicknames: typing.Dict[ int, tuple[ str, int ] ] = {}
        # ipv4, TCP
        self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.socket.setblocking(False)
        self.socket.settimeout(5)

    def acceptConn( self ) -> bool:
        ''' Accept a socket connection, warning this is blocking by default'''
        # this is blocking! It'll wait until someone tries to talk to us!
        
        print( self.socket.getsockname() )
        try:
            conSock, addr = self.socket.accept()
            self.nicknames[ self.conID ] = ( addr, self.port )
            self.conID += 1
            self.connections[ ( addr, self.port ) ] = conSock
            conSock.sendall( (f"Socket connected on ( {addr}:{self.port})").encode() )
        except BlockingIOError:
            pass # pretty useless warning/error
        except TimeoutError:
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
                # only store on a success
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
    
    def getSockByNickname( self, nickname: int ) -> socket.socket:
        ''' Returns the socket object associated with the nickname'''
        try:
            if nickname == 0:
                return self.socket
            
            return self.connections[ self.nicknames[ nickname ] ]
        except Exception:
            logging.error( traceback.format_exc() )
            exit(-1)
            
    def nicknameExists( self, nickname: int ):
        '''' Checks if corresponding nickname exists '''
        # this function exists since geSockByNickname needs to always
        # return a sock instead of  a sock or bool
        
        # 0 meaning to contact our local server
        if nickname in self.nicknames or nickname == 0:
            return True
        return False

    def getMyIpAddr( self ) -> str:
        '''...gets my own ip address'''
        return socket.gethostbyname( socket.gethostname() )
    
    def listAllConns( self ):
        ''' List all socket connections in <nickname> => <ip>:<port> format'''
        for idx, key in enumerate( self.nicknames ):
            print("{idx}. {key} => {self.nicknames[key]} ")
    
    def readMsg( self, sock : socket.socket ):
        ''' Read a socket message'''
        msg = str()
        try:
            msg = sock.recv(1024).decode()
            while( msg ):
                msg += msg
        except Exception:
            pass
            # logging.error( traceback.format_exc() )
            
        # logging.debug( "received: " + msg )
        return msg
    
    def sendConnList( self, sock: socket.socket ):
        ''' Send a list of all of our connections'''
        peers = [ "{ip}:{port}" for ( ip, port ) in self.connections.keys() ]
        try:
            sock.send( ",".join(peers).encode() )
        except Exception:
            logging.error( traceback.format_exc() )
            exit(-1)

    def sendMsg( self, sock: socket.socket, msg : str ) -> bool:
        ''' Send a message through a socket corresponding to the nickname '''
        try:
            sock.sendall( msg.encode() )
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

            
class client(netProc):
    def __init__(self, port: int, sInfo: tuple[ str, int] ):
        super().__init__( port )
        self.sInfo = sInfo

    def getAllSocks( self, nickName : int) -> Union[ str, bool]:
        ''' Sends msg to server @ nickName to send all known sockets back'''
        try:
            sock = self.getSockByNickname( nickName )
            return self.sendMsg( sock, "local_listSocks")
        except TimeoutError:
            return "ERR: Timeout"
        except Exception:
            logging.error(traceback.format_exc())
            return False
    
    def listenLoop( self ):
        '''' Thread runs this function forever '''
        msg = self.readMsg( self.socket )
        if( len(msg) > 0 ):
            logging.debug(f"Client receved msg: {msg}")
        
    def runLoop( self ):
        ''' Do all the client things '''
        # Connect to our local server process
        self.socket.connect( self.sInfo )
        # interactive console thread
        self.cmdThread = threadPlus( shell(client=self).cmdloop() )
        # self.cmdThread = threading.Thread( target = shell(client = self).cmdloop() )
        # listen for server msgs and replies thread
        # TODO: Better processing logic for listenThread?
        # self.listenThread = threading.Thread( target = self.listenLoop() )
        self.listenThread = threadPlus( self.listenLoop() )
        
        self.cmdThread.start()
        self.listenThread.start()
       
        self.cmdThread.join()
        self.listenThread.join()
        print( "Client run loop i shutting down now!" )
        self.socket.close()
        
         
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

    def runLoop( self ):
        ''' Do all the server things '''
        self.acceptConn()
        
        while( True ):
            self.readMsg(self.socket)
        print("Server loop is running, shutting down now!")
        self.shutDown()

class Command(Enum):
    GET_DICT = 0     # Client -> Server: Get nickname dictionary from server
    SEND_MSG = 1     # Client -> Server: Send a message to someone else in the network
    RECV_MSG = 2     # Server -> Client: A message has arrived for the client - pass it on
    KNOCK = 3        # Knock
    HEARTBEAT = 4    # Heartbeat
    KILL_SERVER = 5  # Client -> Server: Kill the server process
    KILL_NETWORK = 6 # Client -> Server, Server -> Server: Kill the entire network by sending the message to all other nodes

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
    
    def encode_message(self, command: Command, data: str = "") -> bytes:
        '''Turn a command and data into the encoded format [length of command + data]:[command][data]'''
        contents: str = str(command.value) + data
        return (str(len(contents)) + ":" + contents).encode()
    
    def decode_message(self, message: bytes) -> tuple[Command, str]:
        '''Turn the encoded format [length of command + data]:[command][data] into (command, data); Also checks the length'''
        m: str = message.decode()
        length: int = int(m.split(":")[0])
        m = m.split(":")[1]
        if len(m) != length:
            raise RuntimeError("Length of received message doesn't match expected length!")
        return (Command(int(m[0])), m[1:] if len(m) > 1 else "")

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
    
    def do_quit(self, args):
        '''exits the shell & terminates client'''
        print("Exiting...")
        # bring down listen thread on quit
        self.client.listenThread.stop()
        # set our thread to be brought down
        self.client.cmdThread.stop()
    
    def do_listSockets(self, sockNickname : str ):
        '''Pools server to return list of sockets <nickname: int | none>'''
        sockNick = int( sockNickname )
        if sockNickname is None: sockNick = 0
        
        if not self.client.nicknameExists( sockNick ):
            print( f" ERR: Nickname {sockNick} is not an existing socket!")
            
        sock = self.client.getAllSocks( sockNick )
        if( sock == False ):
            print(" ERR: Polling server failed")
        else:
            pprint.pp(sock)
       
    def do_makeConnection(self, ipAddr : str, port : int ):
        ''' Connect to a given ipaddress or host'''
        # Sends msg to local server to forward this message to the corresponding socket
        self.client.sendMsg( self.client.socket, f"Knock: {ipAddr},{port}\n")

    # NOTE: cmd.cmd, may pass args as a single string.
    def do_sendMsg(self, sockNickname : str, msg : str ):
        ''' <socketnickname: int> <msg: str>'''
        sockNick = int(sockNickname)
        if not self.client.nicknameExists( sockNick ):
            print( f" ERR: Nickname {sockNick} is not an existing socket!")
        # Sends msg to local server to forward this message to the corresponding socket
        self.client.sendMsg( self.client.socket, f"sendMsg: {msg} \ntarget: {sockNick} ")
     
# script guard, things in this script don't run automatically when imported
if __name__ == "__main__":
    pass