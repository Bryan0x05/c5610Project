import socket
import typing
import traceback
import logging
import cmd
import pprint
from typing import Union
import sys
# import colorama # for different colored text to help tell apart certain messages
# import curses # weird name, it allows us to do some formatting the cmd.cmd terminal. 
# for insance we want incoming messages to be in a different area on the terminal screen.
# Though its a linux-based module

# might be excessive for what we're doing but the idea is we don't have to find debug prints later
# and remove them, we can just change the logging level.
logging.basicConfig(level=logging.DEBUG)

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
        
        print( self.socket.getsockname)
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
            return self.connections[ self.nicknames[ nickname ] ]
        except Exception:
            logging.error( traceback.format_exc() )
            # If this gets exposed as an indirect user command
            # then exit is pretty harsh here
            exit(-1)

    def getMyIpAddr( self ) -> str:
        '''...gets my own ip address'''
        return socket.gethostbyname( socket.gethostname() )
    
    def listAllConns( self ):
        ''' List all socket connections in <nickname> => <ip>:<port> format'''
        for idx, key in enumerate( self.nicknames ):
            print("{idx}. {key} => {self.nicknames[key]} ")
    
    def readMsg( self ):
        ''' Read a socket message'''
        msg : str = self.socket.recv(1024).decode()
        while( msg ):
            msg += msg
            
        logging.debug( "received: " + msg )
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

    def getAllSocks( self ) -> Union[ str, bool]:
        try:
            self.sendMsg(self.socket, "local_listSocks")
            return self.readMsg()
        except TimeoutError:
            return "ERR: Timeout"
        except Exception:
            logging.error(traceback.format_exc())
            return False
        
    def runLoop( self ):
        ''' Do all the client things '''
        self.socket.connect( self.sInfo )
        shell( client = self ).cmdloop()
        # right now we just gracefully shutdown
        print( "Client loop is running, shutting down now!" )
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
            pass
        print("Server loop is running, shutting down now!")
        self.shutDown()

class messageHandler():
    pass

# This might be a 3rd process, or its part of the client process. If that's the case
# maybe all socket communcation should be done through the server process, so we ensure nothing
# on the client is blocking? I think the server part maybe should handle itself
# and the user only interacts with the client portion?
class shell(cmd.Cmd):
    intro = "Type help to get started\n"
    prompt = "shell>"
    
    def __init__(self, client : client ):
        super().__init__()
        self.client = client
    
    def do_quit(self, args):
        '''exits the shell & terminates client'''
        print("Exiting...")
        return True
    
    def do_listSockets(self, arg ):
        ''' prints all sockets'''  
        socks = self.client.getAllSocks()
        if( socks == False ):
            print(" ERR: Polling server failed")
        else:
            pprint.pp(socks)

    def makeConnection(self, arg ):
        ''' Connect to a given ipaddress or host'''
        pass
    
    def sendMsg(self, arg ):
        ''' Send a message to the given socket by nickname? '''
        pass
    
    # If we are doing the server is the point of contact model
    # Then the server should be automatically reading incoming message
    # and if its for the client, to forward it to the client process
    def readMsg(self, arg ):
     ''' Read a message from the given socket'''
     
# script guard, things in this script don't run automatically when imported
if __name__ == "__main__":
    pass
