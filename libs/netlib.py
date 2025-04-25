import socket
import typing
import traceback
import logging
import pprint
from typing import Union, Tuple, List
import threading
from enum import Enum
import os
import subprocess
import pty
import colorama
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import libs.clilib  as clilib
import libs.seclib as seclib
import base64
# import curses # linux based module for terminal formatting

# argument seperator
ASEP = "|"
COM = 0
ARGS = 1
CAVAL = 3

class Command(Enum):
    GET_DICT = 0     # Node <-> Node: Get nickname dictionary from Node
    SEND_MSG = 1     # Node <-> Node: Send a message to someone else in the network
    RECV_MSG = 2     # Node <-> Node: A message has arrived for the client - pass it on
    KNOCK = 3        # Node <-> Node: Connect to network, handshake
    HEARTBEAT = 4    # Node <-> Node: Heartbeat, I'm alive!
    KILL_SERVER = 5  # Node <-> Node: Kill the peer process
    KILL_NETWORK = 6 # Node <-> Node: Kill the entire network by sending the message to all other nodes
    GET_IPS = 7      # Node <-> Node: Give me all the ip addresses you are connected too.
    SHUTDWN_CON = 8      # Node <-> Node: Connected peer is shutting down.
    CHECK_KEY = 9    # Node <-> CA: Validate this public key
    REG_KEY  = 10    # Node <-> CA: Register this key with the CA
    XCHNG_KEY  = 11  # Node <-> Node: Exchange public keys.

class nodeType(Enum):
    PEER = 0
    CA = 1

logging.basicConfig(level=logging.DEBUG)
# TODO: Known issue, threadplus doesn't like arguments. WIP.
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
    # constants for accessing several dictionaries in a more readable fashion
    COM = IN = KEY = 0
    OUT = ARGS = 1
    URI = 2
    
    def __init__( self, port: int, name: str = "_"):
        self.keypub, self.prikey = seclib.securityManager.generatePKCKeys()
        self.keyring = seclib.keyRing()
        self.port = port
        # 0 means the client/server socket in our node
        self.conID = 1
        self.name = name
        self.outboundConns: typing.Dict[ Tuple [ str, int ], socket.socket] = dict()
        self.inboundConns: typing.Dict[ Tuple [ str, int ], socket.socket] = dict()
        # keyed by int, with a 2-tuple of 2tuples each holding str,int pair
        self.nicknames: typing.Dict[ int, Tuple[ Tuple[str, int], Tuple[str, int], str, nodeType ] ] = dict()
        # ipv4, TCP
        self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.socket.setblocking(False)
        self.stop = False
        self.proc = None
        self.type : nodeType = nodeType.PEER
        self.ip = "_"
        self.up = False

    @property
    def uri(self) -> str:
        if self.up:
            return f"{self.ip}:{self.port}"
        raise Exception("URI. URI not set yet")
    
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
            # sacrificial socket to find the lan ip
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
            # ! This addr means we can't connect to processes outside our own machine
            return "127.0.0.1"
    
    def resolveSockNickName( self, insock : socket.socket ):
        ''' Finds the nickname mapping of a incoming socket'''
        inSockNick = -1
        inSockInfo = insock.getsockname()
        for nick, ipAndPort in self.nicknames.items():
            if ipAndPort[self.IN] == inSockInfo:
                inSockNick = nick
        if inSockNick == -1:
            raise Exception(" RESOLVESOCKNICKNAME: couldn't resolve socket nickname for an incoming socket")
        return inSockNick

    def start(self):
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
            # OS should manage this queue, so its non-blocking to us.
            self.socket.listen( 5 )
        except:
            logging.error( traceback.format_exc() )
            exit(-1)
        
    def completeHandshake( self, inSock : socket.socket, msg: Tuple[Command, List[str]] ) -> bool:
        ''''Accepts Step 3 of the handshake reply, terminates handshake'''
        try:
            # the reply handshake should be to an existing already in-use conID
            replyConId = int(msg[self.ARGS][1])
            replyNodeType= nodeType( int( msg[self.ARGS][2]) )
            if not self.nicknameExists( replyConId ):
                logging.error( traceback.format_exc() )
                return False
            
            self.inboundConns[ inSock.getsockname() ] = inSock
            outSockInfo = self.nicknames[ replyConId ][self.OUT]
            uri = self.nicknames[ replyConId ][self.URI]
            self.nicknames[ replyConId ] = ( inSock.getsockname(), (outSockInfo), uri, replyNodeType )
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
        try:
            # Despite accepting this connection the other peer actually doesn't know to listen to this port so its only 1-way.
            inSock, peerAddrAndPort = self.socket.accept()
            logging.debug(f"Accept connection from: {peerAddrAndPort}, on socket: {inSock.getsockname()}")
            inSock.setblocking( False)
            msg = None
            while msg == None:
                msg = self.readMsg( inSock )
                
            if msg is None:
                logging.error( "AcceptConn: msg is none!")
                return False
            elif msg[self.ARGS][0] != 'R' : # step 2 of handshake
                print(f"acceptConn read: {msg}")
                self.inboundConns[ inSock.getsockname() ]  = inSock
                # partial dict update
                self.nicknames[ self.conID ] = (  inSock.getsockname() ,tuple(), "_" , nodeType.PEER )
                # conID and several dicts are updated in here
                return self.handshakeMid( peerAddrAndPort, msg )
            elif msg[self.ARGS][0] == 'R': # step 3 of handshake ( creates duplex conn with 2 sockets )
                return self.completeHandshake( inSock, msg )
            else:
                print("not a valid case in acceptConn")
                return False
        except BlockingIOError:
            # logging.error( traceback.format_exc() ) # uncomment this at your own sanity
            return False
        except TimeoutError:
            # logging.warning("timeout in accept connection")
            return False
        except Exception:
            logging.error( traceback.format_exc() )
            return False
    
    def handshakeMid( self, peerAddrAndPort, msg):
        ''' Deals with handshake step 2'''
        try:
            replyIp = str( peerAddrAndPort[0] )
            replyId = int ( msg[self.ARGS][0] )
            replyPort = int( msg[self.ARGS][1] )
            replyNodeType = nodeType( int( msg[self.ARGS][2] ) )

            # Reach other to peer's "server" socket to establish 2-way connection
            outSock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            outSock.settimeout(5)
            outSock.connect( (replyIp, replyPort) )
            outSock.sendall( messageHandler.encode_message( Command.KNOCK, 'R', replyId, self.type.value ) )
            # I believe this unsets timeout
            # This is fine, the rest of the code operates on a read-again error assumption
            # that non-blocking sockets provide
            outSock.setblocking(False)
            ipAddr, port = outSock.getsockname()
            self.outboundConns[ (ipAddr, port) ] = outSock
            self.nicknames [ self.conID ] = ( self.nicknames[self.conID][self.IN], (ipAddr, port), f"{replyIp}:{replyPort}", replyNodeType )
            self.conID += 1
            print( colorama.Fore.GREEN + "New peer detected, run \"listsockets\" for more info"
                  + colorama.Style.RESET_ALL )
            # reprint shell prompt to make it look clean
            print( clilib.PROMPT, end="", flush=True ) 
            return True
        except Exception:
            logging.error( traceback.format_exc() )
            return False

    def closeConn( self, nickname : int, msgFlag : bool = True ):
        outSock : socket.socket = self.getSockByNickname( nickname )
        inSock = self.inboundConns[ self.nicknames[nickname][self.IN] ]
        
        # Tell the other peer we are closing our sockets pair with them
        # If this function isn't invoked as a response of receiving one.
        if msgFlag:
            self.sendMsg( nickname, messageHandler.encode_message(
                Command.SHUTDWN_CON,
            ))
        outSock.close()
        inSock.close()
        self.inboundConns.pop( self.nicknames[nickname][self.IN])
        self.outboundConns.pop( self.nicknames[nickname][self.OUT] )
        self.nicknames.pop( nickname )

    def connectToHost( self, hostName: str, port: int ) -> bool:
       ''' Connects by host name e.g. www.google.com '''
       return self.connectToIp( socket.gethostbyname( hostName ), port )
    
    def connectToIp( self, targetIpAddr: str, targetPort : int ) -> bool:
        ''' Connects by ipv4 address '''
        try:
            outSock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            outSock.settimeout(10) # default timeout is really long!
            if ( targetIpAddr, targetPort ) in self.outboundConns:
                logging.debug(f"Already connected to {targetIpAddr}:{targetPort}" )
            else:
                outSock.connect( (targetIpAddr, targetPort) )
                # step 1 of the handshake
                outSock.sendall( messageHandler.encode_message(Command.KNOCK, self.conID, self.port, self.type.value ) )
                # replace timeout with non-blocking
                outSock.setblocking( False )
                ipAddr, port = outSock.getsockname()
                self.outboundConns[ (ipAddr, port) ] = outSock
                self.nicknames[self.conID ] = ( tuple(), ( ipAddr, port ), f"{targetIpAddr}:{targetPort}", nodeType.PEER )
                self.conID += 1
                logging.debug(f" Connected to {ipAddr}:{port}, connection nickname: {self.conID} ")
            return True
        # using Exception to exclude base exceptions like SystemExit or keyboardinterrupt
        except TimeoutError:
            print(colorama.Fore.RED+"makeConn timed out!" + colorama.Style.RESET_ALL)
        except Exception:
            # in the block above
            
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
        if nickname in self.nicknames:
            return True
        return False

    def listAllConns( self ):
        ''' List all socket connections in <nickname> => <ip>:<port> format'''
        conns = []
        for idx, key in enumerate( self.nicknames ):
            conns.append( f"{idx}. {key} => {self.nicknames[key]}" )
        return conns        
    
    def readMsg( self, sock : socket.socket ) -> Union[Tuple[Command, List[str]], None]:
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
            # if we have a keyring for it, then we have exchange keys with the sender and must decrypt it
            try:
                senderNick = self.resolveSockNickName(  sock )
                senderURI = self.nicknames[senderNick][self.URI]
                if self.keyring.has(senderURI):
                    # the sender encrypts with our pub key, we must use our private key
                    msg = seclib.securityManager.decrypt( self.prikey, msg )
            except Exception:
                pass
            finally:
                return messageHandler.decode_message( msg )
        else:
            return None
    
    def checkForMsgs( self ):
        ''' Check for a message from all our sockets, returning the first one found'''
        # unitTests seem to getting stuck in the floor when self.connections is empty
        for _, sock in self.inboundConns.items():
            msg = self.readMsg( sock )
            if msg is not None:
                return (msg, sock)
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
                receiverURI = self.nicknames[nickname][self.URI]
                # Encrypt if we have a key for it
                if self.keyring.has( receiverURI ):
                    msg = seclib.securityManager.encrypt( self.keyring[ receiverURI ][self.KEY], msg )
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
        # close all our socket pairs and let our peers know we're going down
        nicks = list( self.nicknames.keys() )
        # This avoids looping over a dictionary while we modify it.
        for nick in nicks:
            self.closeConn( nick )
        # close our server socket
        self.socket.close()
        exit(0)

    def heartbeat_request(self, nickname) -> bool:
        return self.sendMsg(nickname, messageHandler.encode_message(Command.HEARTBEAT, "S", self.ip, self.port) )
    
class CA(netProc):
    def __init__( self, port: int = 0, name: str = "_ " ):
        self.name = name
        self.keypub, self.keypri = seclib.securityManager.generatePKCKeys()
        super().start()
            
    def listenCycle( self ):
        self.acceptConn()
        msg = self.checkForMsgs()
        if msg is None:
            return # contine
        revSock = msg[1]
        msg = msg[0]
        if msg is None:
            return False # effectively continue
        logging.debug(f"CA read: {msg} from {revSock}")
        recvNick = self.resolveSockNickName( revSock )
        
        if msg[COM] == Command.CHECK_KEY:
            uri =  msg[ARGS][1]
            clientCert = msg[ARGS][2]
            if self.keyring.has( uri ) and ( seclib.securityManager.decrypt( self.keypri, clientCert.encode() ) == self.keyring[uri][0] ):
                keyStr = base64.b64encode( seclib.securityManager.serializePubKey( self.keypub ) ).decode()
                self.sendMsg( recvNick, messageHandler.encode_message(Command.CHECK_KEY, "T", uri, keyStr ) )
            else:
                self.sendMsg( recvNick, messageHandler.encode_message(Command.CHECK_KEY, "F" ) )
            self.closeConn( recvNick, True )
        elif msg[COM] == Command.REG_KEY:
            key = seclib.securityManager.decrypt( self.prikey, (msg[ARGS][0]).encode() )
            clientKeyObj = seclib.securityManager.deserializePubKey( key )
            # Register key with the URI of the sender, so they can't easily pretend to be another URI
            if self.keyring.add( self.nicknames[recvNick][self.URI], clientKeyObj, nodeType.PEER, True ):
                cert = seclib.securityManager.encrypt( self.keypub, key )
                self.sendMsg( recvNick, messageHandler.encode_message(Command.REG_KEY, "T", cert ) )
            else:
                self.sendMsg( recvNick, messageHandler.encode_message(Command.REG_KEY, "F" ) )
                self.closeConn( recvNick, True )
        elif msg[COM] == Command.HEARTBEAT:
            # Someone is asking us to send a heartbeat
            if msg[ARGS][0] == "R":
                self.heartbeat_request( int( msg[ARGS][0] ))
            else: # S, someone is telling us their heartbeat
                # print ipaddr, port
                print(f"Heart from { msg[ ARGS ][ 1 ] }:{ msg[ ARGS ][ 2 ]}")
        else:
            logging.warning("CA, default case reached!")
        # close the connection and inform the peer we're closing it.
        # CA will always close the socket.

        # do not stop
        return False
    
    def start( self ):
        self.stop = False
        while not self.stop:
            self.stop = self.listenCycle()

class peer(netProc):
    def __init__(self, port: int = 0, name: str = "_", subProc = False, debug = False, test = False ):
        super().__init__( port, name )
        self.port = port
        self.type = nodeType.PEER
        self.ip = "No ip"
        self.subProc = subProc
        self.test = test
        self.debug = debug
        self.cert : bytes = bytes(0)
        ( logging.getLogger() ).disabled = not debug

    def runLoop( self ):
        ''' Do all the client things '''
        # interactive console thread
        sh = clilib.shell( peer=self)
        self.cmdThread = threadPlus( target = sh.cmdloop, name = "cmdThread" )
        # listen for msgs and replies
        self.listenThread = threadPlus( target = self.listenCycle, name = "listenThread" )

        self.listenThread.start()
        self.cmdThread.start()
        
        self.cmdThread.join()
        self.listenThread.join()
        print( "Peer is shutting down now!" )
        self.up = False
        self.shutDown()

    def listenCycle( self ):
        ''' Do all the server/client things '''
        
        # see if there are any new connections
        self.acceptConn()
        # see if there are any new messages on existing connections
        readMsg: Union[Tuple[Tuple[Command, List[str]], socket.socket], None] = self.checkForMsgs()
        if readMsg is None:
            return # continune
        revSock = readMsg[1]
        recvNick = self.resolveSockNickName( revSock )
        msg: Tuple[Command, List[str]] = readMsg[0]
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
                self.heartbeat_request( int( msg[ARGS][0] ))
            else: # S, someone is telling us their heartbeat
                # print ipaddr, port
                print(f"Heart from { msg[ ARGS ][ 1 ] }:{ msg[ ARGS ][ 2 ]}")
        elif msg[COM] == Command.KNOCK:
            pass #TODO: Maybe try to pull some handshake logic out of acceptConn?
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
        elif msg[COM] == Command.CHECK_KEY:
            self.check_key_listen( msg )
            # TODO: CLI logic for user to request this.
            pass
        elif msg[COM] == Command.REG_KEY:
            ''' Reply from CA after registering our key'''
            self.reg_key_listen( msg )

        elif msg[COM] == Command.XCHNG_KEY:
            self.xchng_key( recvNick, msg)
        elif msg[COM] == Command.SHUTDWN_CON:
            self.shutdwn_con( recvNick )
        else:
            logging.debug("Peer default case reached:")
            pprint.pprint(msg)
    
    @property        
    def CA(self):
        for nick, nickVal in self.nicknames.items():
            if nickVal[CAVAL] == nodeType.CA:
                return nick
        raise Exception("CA nick not found!")
    
    def check_key( self, uri: str, cert ):
        ''' Check local records or Ask CA to validate key'''
        CERT = 2
        if self.keyring.has( uri ):
            if self.keyring[uri][CERT] != True:
                self.sendMsg( self.CA, messageHandler.encode_message(Command.CHECK_KEY, uri, cert))
                print(colorama.Fore.GREEN, f"Validating key for {uri} with CA..." + colorama.Style.RESET_ALL )
            else:
                return True
        else:
           return False
    
    def check_key_listen( self,  msg : Tuple[Command, List[str]] ) -> bool:
        ''' listen to reply from CA after asking to validate the provided cert for a peer's pub key'''
        uri = msg[ARGS][1]
        if (msg[ARGS][0]) == "T":
            key = msg[ARGS][2]
            keyObj = seclib.securityManager.deserializePubKey( key.encode() )
            self.keyring.add( uri, keyObj, nodeType.PEER, True )
        else:
            targetNick = -1
            for nick, nickVal in self.nicknames.items():
                if  nickVal[self.URI] == uri: 
                    targetNick = nick
                    break
            if targetNick == -1:
                logging.warning("Peer, check_key failed to find targetnick")
            else:
                print(colorama.Fore.RED+f"ERR: CA was unable to validate the certificate for: {targetNick} !"+colorama.Style.RESET_ALL)
            return False
        print(colorama.Fore.GREEN, f"Validated key for {uri}" + colorama.Style.RESET_ALL )
        return True
    
    def reg_key_listen(self,  msg : Union[Tuple[Command, List[str]], None] = None) -> bool:
        ''' The REG_KEY function, that listens for the CA reply to the REG_KEY command message'''
        if msg == None: return False
        if (msg[ARGS][0]) == "T":
            self.cert = (msg[ARGS][1]).encode()
            return True
        else:
            print(colorama.Fore.RED+"ERR: CA was unable to register our key!"+colorama.Style.RESET_ALL)
            return False
    
    def shutdwn_con( self, recvNick : int ) -> bool:
            # peer shutdowm their socket peer with us, update our local dictionary to reflect that
                self.closeConn( recvNick, False )
                return True
    
    def reg_key( self ):
        # find our CA ( or the first CA we see )
        try:
            keyStr = base64.b64encode( seclib.securityManager.serializePubKey( self.keypub ) ).decode()
            self.sendMsg( self.CA, messageHandler.encode_message(Command.REG_KEY, keyStr) )
            return True
        except:
            print(colorama.Fore.RED+"ERR: CA was unable to register our key!"+colorama.Style.RESET_ALL)
        return False
            
    
    def xchng_key(self, recvNick : int, msg : Union[Tuple[Command, List[str]], None] = None) -> bool:
        ''' Exchange keys with another peer'''
        # if we are starting the xchange:
        if msg == None:
            uri = self.nicknames[ recvNick ][self.URI]
            # convert our key object to bytes, then decode into str to be compadiable with message handler
            keyStr = base64.b64encode( seclib.securityManager.serializePubKey( self.keypub ) ).decode()
            self.sendMsg( recvNick ,messageHandler.encode_message(Command.XCHNG_KEY, keyStr, self.cert, "R" ) )
        else: # we are receiving an incoming xchng 
            recvKey = msg[ARGS][0]
            recvCert = msg[ARGS][1]
            replyFlag = msg[ARGS][2] # R= requesting reply, S = Sending ( i.e. don't reply)
            uri = self.nicknames[ recvNick ][self.URI]
            recvKeyObj: RSAPublicKey = seclib.securityManager.deserializePubKey( recvKey.encode() )
            
            if not self.keyring.has( uri ):
                # TODO: validate certs before adding
                # ?: CA / anti-CA logic if the request has come from that peer type(?)
                self.keyring.add( uri, recvKeyObj, nodeType.PEER )

            if replyFlag == "R":
                keyStr = seclib.securityManager.serializePubKey( self.keypub ).decode()
                self.sendMsg( recvNick, messageHandler.encode_message(Command.XCHNG_KEY, keyStr, self.cert, "S" ) )
        
        return True
    
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
         
    def knock(self, ip_addr, port) -> bool:
        print(colorama.Fore.GREEN, f"Connecting to {ip_addr}:{port}..." + colorama.Style.RESET_ALL )
        if self.connectToIp( ip_addr, port ):
            print(colorama.Fore.GREEN, f"Connected to {ip_addr}:{port}" + colorama.Style.RESET_ALL )
            return True
        else:
            print( colorama.Fore.RED, f"ERR: Failed to connect to {ip_addr}:{port}" + colorama.Style.RESET_ALL )
            return False

    def start( self ) :
        ''' Bind the socket and start the peer '''
        self.up = True

        if self.subProc == True:
            # mfd, sfd are file descriptprs created from pty.openpty() in which case they shuold be ints.
            self.masterFd, self.servantFd = pty.openpty()
            debug = "F" if self.debug == False else "T"
            command = [ "python3", "setupNode.py", "F", debug ]
            self.proc = subprocess.Popen(
                command, stdin=self.masterFd, stdout = subprocess.PIPE, 
                stderr = subprocess.PIPE, text = True )
            return

        super().start()
        
        # don't do anything in an interactive function if this flag is on
        if self.test:
            return
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
        if self.proc == None:
            raise ValueError("ERR: Trying to readProc from subprocess when none exists!")
        return self.proc.stdout.read() # type: ignore
        
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


        
# script guard, things in this script don't run automatically when imported
if __name__ == "__main__":
    pass