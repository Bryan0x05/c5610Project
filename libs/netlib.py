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
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
import libs.clilib  as clilib
import libs.seclib as seclib
import base64
import datetime
import builtins
# import curses # linux based module for terminal formatting

# argument seperator
ASEP = "|"
COM = 0
ARGS = 1
CAVAL = 3
# allows custom error object for easier catching
class CANotFound(Exception):
    pass

class Command(Enum):
    GET_DICT = 0     # Node <-> Node: Get nickname dictionary from Node
    SEND_MSG = 1     # Node <-> Node: Send a message to someone else in the network
    RECV_MSG = 2     # Node <-> Node: A message has arrived for the client - pass it on
    KNOCK = 3        # Node <-> Node: Connect to network, handshake
    HEARTBEAT = 4    # Node <-> Node: Heartbeat, I'm alive!
    KILL_SERVER = 5  # Node <-> Node: Kill the peer process
    KILL_NETWORK = 6 # Node <-> Node: Kill the entire network by sending the message to all other nodes
    GET_URIS = 7      # Node <-> Node: Give me all the URIS you are connected too.
    SHUTDWN_CON = 8      # Node <-> Node: Connected peer is shutting down.
    CHECK_KEY = 9    # Node <-> CA: Validate this public key
    REG_KEY  = 10    # Node <-> CA: Register this key with the CA
    XCHNG_KEY  = 11  # Node <-> Node: Exchange public keys.
    XCHNG_CERT =  12 # Node <->: Exchange public key certs.
class nodeType(Enum):
    PEER = 0
    CA = 1

logging.basicConfig(level=logging.DEBUG)
# BUG: Threadplus doesn't like function arguments, however, we never invoke it with function arguments so this bug is low pri
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
    # TODO: Make these constants global!
    COM = IN = KEY = 0
    OUT = ARGS = 1
    URI = 2
    
    def __init__( self, port: int, name: str = "_", keySize : int = 4096):
        self.keyring = seclib.keyRing()
        self.pubkey, self.prikey = seclib.securityManager.generatePKCKeys( keySize )
        self.compressKey = seclib.securityManager.generateCompressionKey()
        self.port = port
        # 0 means the client/server socket in our node
        self.conID = 1
        self.name = name
        self.outboundConns: typing.Dict[ Tuple [ str, int ], socket.socket] = dict()
        self.inboundConns: typing.Dict[ str, socket.socket] = dict()
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
        self.cert = bytes(0)

    @property
    def uri(self) -> str:
        if self.up:
            return f"{self.ip}:{self.port}"
        raise Exception("URI. URI not set yet")
    
    @property        
    def CA(self) -> int:
        for nick, nickVal in self.nicknames.items():
            if nickVal[CAVAL] == nodeType.CA:
                return nick
        raise CANotFound("CA nick not found!")
    
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
        ''' Finds the nickname mapping of an incoming socket'''
        inSockNick = -1
        # inbounds sockets will have the same ip and port matching our listening oscket
        # They however should have different peer sockets
        inSockInfo = insock.getpeername()
        for nick, nickValue in self.nicknames.items():
            inS = self.inboundConns[ nickValue[ self.URI ] ] 
            if inS.getpeername() == inSockInfo:
                inSockNick = nick
        if inSockNick == -1:
            raise Exception(" RESOLVESOCKNICKNAME: couldn't resolve socket nickname for an incoming socket")
        return inSockNick

    def start(self):
        self.up = True
        try:
            # dis-allow socket re-use
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
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

    def acceptConn( self ) -> bool:
        ''' Accept a socket connection, warning this is blocking by default'''
        try:
            # Despite accepting this connection the other peer actually doesn't know to listen to this port so its only 1-way.
            inSock, peerAddrAndPort = self.socket.accept()
            inSock.setblocking( False)
            msg = None
            
            while msg == None:
                msg = self.simpleReadMsg( inSock  )
                
            if msg is None:
                logging.error( "AcceptConn: msg is none!")
                return False
            # happens on peer 2 ( where peer1 starts the connection by connecting to peer 2 )
            elif msg[self.ARGS][0] != 'R' : # step 2 of handshake
                # First time seeing this inbound socket update our local dicts to reflect the
                # New inbound socket
                self.nicknames[ self.conID ] = (  inSock.getsockname() , tuple(), "_" , nodeType.PEER )
                logging.debug(f"Accept connection from: {peerAddrAndPort}, on socket: {inSock.getsockname()}, nickname: {self.conID}")

                # Read handshake msg, make an outbound socket and update dictionary accordlying
                return self.handshakeMid( inSock, peerAddrAndPort, msg )
            # happens on peer 1 ( peer 2 replies to peer 1's connection with its own )
            elif msg[self.ARGS][0] == 'R': # step 3 of handshake ( creates duplex conn with 2 sockets )
                # NOTE: Doesn't make a new entry, instead using the existing connectToIP made
                replyConId = int(msg[self.ARGS][1])
                replyNodeType = nodeType( int ( ( msg[self.ARGS][2] ) ) )
                return self.completeHandshake( inSock, replyConId, replyNodeType )
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
    
    def handshakeMid( self, inSock, peerAddrAndPort, msg):
        ''' Deals with handshake step 2'''
        try:
            # information form socket peer
            replyIp = str( peerAddrAndPort[0] )
            # msg data
            replyId = int ( msg[self.ARGS][0] )
            replyPort = int( msg[self.ARGS][1] )
            replyNodeType = nodeType( int( msg[self.ARGS][2] ) )

            # Reach other to peer's "server" socket to establish 2-way connection
            outSock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            outSock.settimeout(5) # timeout is very long otherwise, we're running everything locally it should not be long.
            self.inboundConns[ f"{replyIp}:{replyPort}" ]  = inSock
            outSock.connect( (replyIp, replyPort) )

            # set non-blocking behavior expected by the rest the program, overwritting the timeout.
            outSock.setblocking(False)
            # get our outsock information & update dictionaries
            ipAddr, port = outSock.getsockname()
            self.outboundConns[ (ipAddr, port) ] = outSock
            # complete Peer2(receiving) dictionary entry
            self.nicknames [ self.conID ] = ( self.nicknames[self.conID][self.IN], (ipAddr, port), f"{replyIp}:{replyPort}", replyNodeType )
            # Give peer1, the final handshake msg
            self.sendMsg( self.conID, messageHandler.encode_message( Command.KNOCK, 'R', replyId, self.type.value ) )
            print( colorama.Fore.GREEN + "New peer detected, run \"listsockets\" for more info"
                  + colorama.Style.RESET_ALL )
            # reprint shell prompt to make it look clean
            print( clilib.PROMPT, end="", flush=True )
            self.conID += 1
            return True
        except Exception:
            logging.error( traceback.format_exc() )
            return False
        
    def completeHandshake( self, inSock : socket.socket, replyConId : int, replyNodeType : nodeType ) -> bool:
            ''''Accepts Step 3 of the handshake reply, peer 1 accepts an inbound socket from peer 2'''
            try:
                # the reply handshake should be to an existing already in-use conID
                if not self.nicknameExists( replyConId ):
                    logging.error(f"completeHandshake: No existing nickname for conID {replyConId}")
                    return False
                # Retrieve the outbound socket info that was created earlier in handshakeMid
                outSockInfo = self.nicknames[replyConId][self.OUT]
                uri = self.nicknames[replyConId][self.URI]
                
                # Register the inbound socket
                self.inboundConns[ uri ] = inSock

                # Update the nickname entry to store both inbound and outbound sockets
                self.nicknames[replyConId] = (inSock.getsockname(), outSockInfo, uri, replyNodeType)
                logging.debug(f"Handshake complete for conID {replyConId} between {inSock.getsockname()} and {outSockInfo}")
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
            
    def closeConn( self, nickname : int, msgFlag : bool = True ):
        # TODO: Valid functionality with 2+ connections
        '''
        logging.debug(f"nickname: {self.nicknames}")
        logging.debug("="*20)
        logging.debug(f"inboundConns: {self.inboundConns}")
        logging.debug("="*20)
        logging.debug(f"outboundConns: {self.outboundConns}")
        '''
        outSock : socket.socket = self.getSockByNickname( nickname )
        inSock = self.inboundConns[ self.nicknames[nickname][self.URI] ]
        
        # Tell the other peer we are closing our sockets pair with them
        # If this function isn't invoked as a response of receiving one.
        if msgFlag:
            self.sendMsg( nickname, messageHandler.encode_message(
                Command.SHUTDWN_CON,
            ))
        outSock.close()
        inSock.close()
        self.inboundConns.pop( self.nicknames[nickname][self.URI])
        self.outboundConns.pop( self.nicknames[nickname][self.OUT] )
        self.nicknames.pop( nickname )

    def connectToHost( self, hostName: str, port: int ) -> bool:
        ''' Connects by host name e.g. www.google.com '''
        return self.connectToIp( socket.gethostbyname( hostName ), port )
    
    def connectToIp( self, targetIpAddr: str, targetPort : int ) -> bool:
        ''' Connects by ipv4 address, adds URI to local dictionary '''
        try:

            if ( targetIpAddr, targetPort ) in self.outboundConns:
                logging.debug(f"Already connected to {targetIpAddr}:{targetPort}" )
                return False
            else:
                uri = f"{targetIpAddr}:{targetPort}"
                if uri == self.uri:
                    logging.warning(f"{self.uri} tried to connect to itself, aborting!")
                    return False
                
                outSock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
                outSock.settimeout(10) # default timeout is really long otherwise!
                outSock.connect( (targetIpAddr, targetPort) )
                # replace timeout with non-blocking
                outSock.setblocking( False )
                ipAddr, port = outSock.getsockname()
                self.outboundConns[ (ipAddr, port) ] = outSock

                # partial update, setting up  place holder inbound, outbound socket, target uri, target nodeType(assumed peer for now) 
                self.nicknames[ self.conID ] = ( tuple(), ( ipAddr, port ), uri, nodeType.PEER )
                # step 1 of the handshake
                self.sendMsg( self.conID,  messageHandler.encode_message(Command.KNOCK, self.conID, self.port, self.type.value ))
                logging.debug(f" Connected to {ipAddr}:{port}, connection nickname: {self.conID} ")
                self.conID += 1
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
                ''' ========= PROTOHEADER(msg) ==============
                isMsgEncrypted | splitLoc | compressKey | msg
                =============================================
                isMsgEncrypted - a byte value of a bool, saying if the following message is encrypted ( meaning if compressKey & msg are )
                splitLoc - The byte index that delimits the split between compressKey & msg
                compressKey - the key for the symmetric fernet encryption, also used to shorten all messages.
                msg - the messageHandler header, that contains a Command enum and arguments for the receiver.
                
                This is called the protoheader as its a low level header that encapulsates the existing header created from messageHandler.
                With some additional, often non-encrypted information.
                '''
                
                # check first byte for encryption flag
                isMsgEncrypted = bool(msg[0])
                # grab the 2 bytes to find the index of the split between compress key and msg
                splitLoc = int.from_bytes(msg[1:3], 'big')
                compressKeyBytes = msg[3:splitLoc]
                #  grab the msg
                msgBytes = msg[splitLoc+1:]
                
                senderNick = self.resolveSockNickName(  sock )
                senderURI = self.nicknames[senderNick][self.URI]
                if self.keyring.has(senderURI) and isMsgEncrypted:
                    # logging.debug(f"\n\nprikey length: {self.prikey.key_size}\n\n compress key length {len(compressKeyBytes)}")
                    # logging.debug("\n reading encrypted msg!\n")
                    compressKey = seclib.securityManager.decrypt(self.prikey, compressKeyBytes)
                    # the sender encrypts with our pub key, we must use our private key
                    msg = seclib.securityManager.decrypt( self.prikey, msgBytes  )
                elif isMsgEncrypted:
                    print(colorama.Fore.RED, f"ERR: Failed to read encrypted msg from: {sock.getsockname()}, no key in key ring!"
                          + colorama.Style.RESET_ALL)
                    return None
                else: # not encrypted
                    msg = msgBytes
                    compressKey = compressKeyBytes
                
                msg = base64.b64decode(msg)
                compressKey: bytes = base64.b64decode(compressKey.decode())
                uncompressedMsg = seclib.securityManager.uncompress( compressKey, msg )
                return messageHandler.decode_message( uncompressedMsg )
            except Exception:
                logging.error( traceback.format_exc() )
        else:
            return None
    
    def simpleReadMsg(self, sock : socket.socket ):
        ''' A "lower-level' read Msg, doesn't decrypt, check keys or existing dictionaries'''
        msg : bytes = bytes()
        incMsg : bytes = bytes()
        try: # NOTE: Since we read till failure, DoS attack is trival
            while len( incMsg := sock.recv(1024) ) > 0:
                    msg += incMsg
        except ( socket.timeout, BlockingIOError ): # Treating timeout as an async try again error
            pass
        except OSError:
            logging.warning( traceback.format_exc() )
        except Exception:
            logging.error( traceback.format_exc() )
        if len(msg) > 0:
            try:
                # parse protoheader to get compression key, check for encryption and message.
                # check first byte for encryption flag
                isMsgEncrypted = bool(msg[0])
                # grab the 2 bytes to find the index of the split between compress key and msg
                splitLoc = int.from_bytes(msg[1:3], 'big')
                compressKey = msg[3:splitLoc]
                msg = msg[splitLoc+1:]
                
                compressKey = base64.b64decode(compressKey.decode())
                # simple read doesn't handle encrpytion
                if isMsgEncrypted == True: raise ValueError("isMsgEncrypted is True in simpleReadMsg")
                # msg is sent in a text-safe format, since the "compression" relies on it.
                msg = base64.b64decode(msg)
                uncompressedMsg = seclib.securityManager.uncompress( compressKey, msg )
                return messageHandler.decode_message( uncompressedMsg )
            except Exception:
                logging.error( traceback.format_exc() )
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

    def sendConnURIs( self, nickname: int ) -> bool:
        ''' Send a list of all URIS of nodes we are connected to'''
        peers: list[str] = [ entry[self.URI] for ( _, entry ) in self.nicknames.items() ]
        # S = sending, as in sending the info, R = requesting, requesting the info
        return self.sendMsg( nickname, messageHandler.encode_message(Command.GET_URIS, "S", *peers) )

    def sendMsg( self, nickname: int, msg : bytes, doEncrypt : bool = True ) -> bool:
        ''' Send a message through a socket corresponding to the nickname '''
        
        ''' ========= PROTOHEADER(finalMsg) ==============
        isMsgEncrypted | splitLoc | compressKey | msg
        =============================================
        isMsgEncrypted - a byte value of a bool, saying if the following message is encrypted ( meaning if compressKey & msg are )
        splitLoc - The byte index that delimits the split between compressKey & msg
        compressKey - the key for the symmetric fernet encryption, also used to shorten all messages.
        msg - the messageHandler header, that contains a Command enum and argument for the receiver.
        
        This is called the protoheader as its a low level header that encapulsates the existing header created from messageHandler.
        With some additional, often non-encrypted information.
        '''
        isMsgEncrypted =  False
        if self.nicknameExists( nickname ):
            try:
                # ! compress message to make fit under RSA size requirements keySize(4096) - 2 *  hash size(32) - 2 (which is 446 in our case)
                msg = base64.b64encode(seclib.securityManager.compress( self.compressKey, msg))
                encryptedMsg = bytes(0)
                # Fernet is byte-based, convert to text-safe.
                packagedCompKey = base64.b64encode(self.compressKey)
                receiverURI = self.nicknames[nickname][self.URI]
                # Encrypt if we have a key for it
                if self.keyring.has( receiverURI ) and doEncrypt :
                    isMsgEncrypted = True
                    keyObj =  self.keyring[ receiverURI ][self.KEY]

                    encryptedMsg = seclib.securityManager.encrypt( self.keyring[ receiverURI ][self.KEY], msg )
                    packagedCompKey = seclib.securityManager.encrypt( self.keyring[ receiverURI ][self.KEY], packagedCompKey )
                
                finalMsg = int(isMsgEncrypted).to_bytes(1, 'big')
                finalMsg += (len(packagedCompKey) + 3).to_bytes(2, 'big')
                finalMsg += packagedCompKey
                finalMsg += ASEP.encode()
                if len(encryptedMsg) < 1:
                    finalMsg += msg
                else:
                    finalMsg += encryptedMsg
                logging.debug( f"sending, finalMsg len: {len(finalMsg)}")
                self.getSockByNickname(nickname).sendall( finalMsg )
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
    
    def xchng_key(self, recvNick : int, msg : Union[Tuple[Command, List[str]], None] = None) -> bool:
        ''' Exchange keys with another node'''
        CERT = 2
        # if we are starting the xchange:
        if msg == None:
            uri = self.nicknames[ recvNick ][self.URI]
            # convert our key object to bytes, then decode into str to be compadiable with message handler
            keyStr = seclib.securityManager.serializePubKey( self.pubkey ).decode()
            ourCert = ( base64.b64encode( self.cert ) ).decode()
            if not self.sendMsg( recvNick ,messageHandler.encode_message(Command.XCHNG_KEY, keyStr, ourCert, "R" ), False ):
                logging.error( "xchng_key send msg failed!" )
                logging.error( traceback.format_exc )
                return False
            return True
        else: # we are receiving an incoming xchng
            recvKey = msg[ARGS][0]
            recvCert = msg[ARGS][1]
            replyFlag = msg[ARGS][2] # R= requesting reply, S = Sending ( i.e. don't reply)
            uri = self.nicknames[ recvNick ][self.URI]
            
            recvKeyObj: RSAPublicKey = seclib.securityManager.deserializePubKey( recvKey.encode() )
            if not self.keyring.has( uri ):
                self.keyring.add( uri, recvKeyObj, nodeType.PEER )
                '''
                if len(recvCert) > 0 and self.CA :
                    # Ask CA to check certificate
                    # self.check_key( uri, recvCert, self.CA )
                    stime = datetime.datetime.now()
                    # wait for listen thread to hear back from CA(spin lock), which will then set the cert field to non-zero.
                    while len(self.keyring[uri][CERT]) == 0:
                        etime = datetime.datetime.now() - stime
                        if etime > datetime.timedelta( seconds=10 ):
                            print( colorama.Fore.RED + f" Timedout Validating {uri} public key!" + colorama.Style.RESET_ALL)
                            break
                    
                    # if CA has certified the key
                    if len(self.keyring[uri][CERT]) > 1:
                        print( colorama.Fore.GREEN, f"CA has validated key for {uri}!" + colorama.Style.RESET_ALL )
                    else:
                        pass # cert failure print already handle in check_key_listen
                    '''

            if replyFlag == "R":
                keyStr = seclib.securityManager.serializePubKey( self.pubkey ).decode()
                ourCert = ( base64.b64encode( self.cert ) ).decode()
                if not self.sendMsg( recvNick, messageHandler.encode_message(Command.XCHNG_KEY, keyStr, ourCert, "S"), False ):
                    logging.error( "xchng_key send msg failed!" )
                    logging.error( traceback.format_exc )
                    return False
                
            print(colorama.Fore.GREEN, f"Keys exchanged with Node {recvNick}! All messages with Node {recvNick} will now be encrypted!"
                  " To certify the key please see \"checkKey\" command"
                + colorama.Style.RESET_ALL)
            print( clilib.PROMPT, end="", flush=True )
        return True

    def check_key( self, uri: str, cert : str, targetNick : int ) -> bool:
        ''' Send uri + cert to targetNick (should be our CA) to validate the cert for the provided key
        This function is overloaded in the CA, so be weary of changing the top level arguments here'''
        CERT = 2
        if targetNick == self.CA:
            print(colorama.Fore.RED, f"Cannot checkKey our own CA" + colorama.Style.RESET_ALL )
            return True
        if self.keyring.has( uri ):
            # if we haven't already successfuly verified ( cert field in keyring is being overloaded as a flag in this instance )
            if len( self.keyring[uri][CERT] ) <= 1:
                logging.debug("Calling send in check_key!")
                # Send cert for CA evaluation
                self.sendMsg( self.CA, messageHandler.encode_message(Command.CHECK_KEY, uri, cert))
                print(colorama.Fore.GREEN, f"Cert of {uri} sent to CA, waiting..." + colorama.Style.RESET_ALL )
                return True
            else:
                print(colorama.Fore.GREEN, f"Cert for {uri} is already validated" + colorama.Style.RESET_ALL )
                return True
        else:
            print(colorama.Fore.RED, f"No key for {uri} to validate, please use \"exchangeKey\" first" + colorama.Style.RESET_ALL )
            return False

class CA(netProc):
    CERT = 2
    def __init__( self, port: int = 0, name: str = "_" , debug = False ):
        self.name = name
        self.keypub, self.prikey = seclib.securityManager.generatePKCKeys( 4_184)
        super().__init__(port, name, keySize = 4_096)
        self.type = nodeType.CA
        ( logging.getLogger() ).disabled = not debug


    def listenCycle( self ):
        self.acceptConn()
        recvMsg: Union[Tuple[Tuple[Command, List[str]], socket.socket], None] = self.checkForMsgs()
        if recvMsg is None:
            return # contine
        msg: Tuple[Command, list[str]] = recvMsg[0]
        if msg is None:
            return False # effectively continue
        
        # filtering out the socket from msg
        revSock = recvMsg[1]
        recvNick = self.resolveSockNickName( revSock )
        logging.debug(f"CA read: {msg[0]} from {recvNick}\n")
        if msg[COM] == Command.XCHNG_KEY:
            ''' Exchange keys with peer for encrypted communcation.
            Peer auto xchg_keys with CA when running CLI regKey command.'''
            self.xchng_key( recvNick, msg )
        
        elif msg[COM] == Command.CHECK_KEY:
            uri =  msg[ARGS][0]
            clientCert = msg[ARGS][1]  
            self.check_key( uri, clientCert, recvNick)

        elif msg[COM] == Command.REG_KEY:
           self.reg_key( recvNick )

        elif msg[COM] == Command.HEARTBEAT:
            # Someone is asking us to send a heartbeat
            if msg[ARGS][0] == "R":
                self.heartbeat_request( int( msg[ARGS][0] ))
            else: # S, someone is telling us their heartbeat
                # print ipaddr, port
                print(f"Heart from { msg[ ARGS ][ 1 ] }:{ msg[ ARGS ][ 2 ]}")
        else:
            logging.warning("CA, default case reached!")
        # do not stop
        return False
    def reg_key( self, recvNick: int )->bool:
        '''Produce and return a certificate to the requesting peer'''
        try:
            clientKey = self.keyring[ self.nicknames[recvNick][self.URI]][self.KEY]
            clientKeyBytes = seclib.securityManager.serializePubKey( clientKey )
            # compressedData = seclib.securityManager.compress(  self.compressKey, recvKey )
            hashedKey = seclib.securityManager.hash( clientKeyBytes )
            # needs to be hashed, since peer and CA have same size key
            # ! cryptography module only allows encryption with pub key.
            cert = seclib.securityManager.encrypt( self.keypub, hashedKey )
            # needs to be hash, sends sendMsg might try encrypting the message ( same size issue again)
            cert = seclib.securityManager.hash( cert )
            # cache cert on file
            self.keyring.updateKey(  self.nicknames[recvNick][self.URI], cert )
            encodedCert = base64.b64encode( cert )
            self.sendMsg( recvNick, messageHandler.encode_message(Command.REG_KEY, "T", encodedCert.decode() ) )
            return True
        except:
            print( colorama.Fore.RED + "Cert generation failed" + colorama.Style.RESET_ALL )
            self.sendMsg( recvNick, messageHandler.encode_message(Command.REG_KEY, "F" ) )
            return False
    # TODO: check_key, is never succesfully validating the key(?) Could be peer side issue
    def check_key( self, uri, cert, targetNick ) ->bool:
        ''' Check peer provided cert, with the one we reconstruct with information on keyring'''
        cachedCert = None
        cert = base64.b64decode( cert.encode() )
        if self.keyring.has( uri ):
            cachedCert = self.keyring[uri][self.CERT]
            if cachedCert == cert:
                cachedCert =  base64.b64encode( cachedCert ).decode()
                self.sendMsg( targetNick, messageHandler.encode_message(Command.CHECK_KEY, "T", uri, cachedCert ) )
                return True
        # catch all, failure state
        msgToSend = messageHandler.encode_message(Command.CHECK_KEY, "F", uri )
        logging.debug(f"certRecv: {cert}")
        logging.debug("cachedCert" + f"{cachedCert}" )
        logging.debug("msgToSend" + f"{msgToSend}" )
        self.sendMsg( targetNick, msgToSend )
        return False
            
    def start( self ):
        super().start()
        print(f"{self.name} is listening on {self.ip}:{self.port}")
        # Disable regular non-log prints for the CA. If debug is not toggled on, no prints will be visible form the CA.
        # This stops it from printing out some CLI formating code that the peer uses.
        builtins.print = lambda *args, **kwargs: None
        self.stop = False
        while not self.stop:
            self.stop = self.listenCycle()

class peer(netProc):
    def __init__(self, port: int = 0, name: str = "_", subProc = False, debug = False, test = False ):
        super().__init__( port, name, keySize = 4_096 )
        self.port = port
        self.type = nodeType.PEER
        self.ip = "No ip"
        self.subProc = subProc
        self.test = test
        self.debug = debug
        # thread events used to block effeciently block CLI without spin locking to avoid running afoul of GIL mutex.
        self.caKeyExchanged = threading.Event()
        self.waitingForCert = threading.Event()
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
        logging.debug(f"Server read command: {msg[0]}")
        
        if msg[COM] == Command.KILL_SERVER:
            self.kill_peer()
        elif msg[COM] == Command.KILL_NETWORK:
            self.kill_network()
        elif msg[COM] == Command.SEND_MSG: # For relaying messages
            pass
            # nick = int( msg[ARGS][0] )
            # self.sendMsg( nick, messageHandler.encode_message(Command.RECV_MSG, " ".join(msg[ARGS][1:]) ))
        elif msg[COM] == Command.RECV_MSG:
            msgRecv = msg[ARGS][0:]
            uri = self.nicknames[recvNick][self.URI]
            encryptFlag = self.keyring.has(uri)
            certFlag = encryptFlag and len(self.keyring[uri][2]) > 1
            
            if encryptFlag and certFlag:
                print(colorama.Fore.CYAN,f"From: {uri}(encrypted+certified), msg: {msgRecv}" + colorama.Style.RESET_ALL )
            elif encryptFlag and not certFlag:
                print( colorama.Fore.MAGENTA + f"From: {uri}(uncertified but encrypted), msg: {msgRecv}" + colorama.Style.RESET_ALL )
            else:
                print(colorama.Fore.BLUE + f"From: {uri}(plaintext), msg: {msgRecv}" + colorama.Style.RESET_ALL )
            # for CLI formatting
            print( clilib.PROMPT, end="", flush=True )

        elif msg[COM] == Command.HEARTBEAT:
            # Someone is asking us to send a heartbeat
            if msg[ARGS][0] == "R":
                self.heartbeat_request( int( msg[ARGS][0] ))
            else: # S, someone is telling us their heartbeat
                # print ipaddr, port
                print(f"Heart from { msg[ ARGS ][ 1 ] }:{ msg[ ARGS ][ 2 ]}")
        elif msg[COM] == Command.KNOCK:
            pass #TODO: Maybe try to pull some handshake logic out of acceptConn?
        elif msg[COM] == Command.GET_URIS:
            # requesting us to give the list
            if msg[ ARGS ][ 0 ] == "R":
                self.sendConnURIs( recvNick )
            # sending us a list
            if msg[ ARGS ][ 0 ] == "S":
                self.readURIsAndConnect( msg )
        elif msg[COM] == Command.CHECK_KEY:
            self.check_key_listen( msg )
            # TODO: CLI logic for user to request this.
            pass
        elif msg[COM] == Command.REG_KEY:
            ''' Reply from CA after reg istering our key'''
            self.reg_key_listen( msg )
        elif msg[COM] == Command.XCHNG_KEY:
            self.xchng_key( recvNick, msg)
            # set the flag regKey checks to see if it can procede
            if self.nicknames[recvNick][3] == nodeType.CA:
                self.caKeyExchanged.set()
        elif msg[COM] == Command.XCHNG_CERT:
            self.certExchange( recvNick, msg)
        elif msg[COM] == Command.SHUTDWN_CON:
            self.shutdwn_con( recvNick )
        else:
            logging.debug("Peer default case reached:")
            pprint.pprint(msg)
    
    def requestURIs(self, nickname) -> bool:
        return self.sendMsg( nickname, messageHandler.encode_message(Command.GET_URIS, "R") )

    
    def readURIsAndConnect( self, msg ) -> bool:
        uris: List[str] = msg[ ARGS ][ 1: ]
        existingURIs = [ value[self.URI] for _,value in self.nicknames.items()]
        existingURIs.append(self.uri)
        print(f"uris: {uris}")
        print(f"existingURIs: {existingURIs}")

        for uri in uris:
            if uri not in existingURIs:
                ip, port = uri.split(":")
                if self.connectToIp( ip, int(port) ):
                    print( colorama.Fore.GREEN + "URI Recieved, connected to a new peer" +
                          " run \"listsockets\" for more info"
                        + colorama.Style.RESET_ALL )
                else:
                    print(colorama.Fore.RED, f"ERR: Failed to connect to: {ip}:{self.port}" + colorama.Style.RESET_ALL)
                    return False
        return True
    
    def check_key_listen( self,  msg : Tuple[Command, List[str]] ) -> bool:
        ''' listen to reply from CA after asking to validate the provided cert for a peer's pub key'''
        uri = msg[ARGS][1]
        if (msg[ARGS][0]) == "T":
            cert = msg[ARGS][2]
            cert = base64.b64decode( cert.encode() )
            print(colorama.Fore.GREEN+f"CA validated the certificate for: {uri} !"+colorama.Style.RESET_ALL)
            return self.keyring.updateKey( uri, cert )
        else:
            # overload the cert field as a flag, to signal invalid cert
            self.keyring.updateKey( uri, bytes(1) )
            print(colorama.Fore.RED+f"ERR: CA was unable to validate the certificate for: {uri} !"+colorama.Style.RESET_ALL)
            return False
    
    def reg_key_listen(self,  msg : Union[Tuple[Command, List[str]], None] = None) -> bool:
        ''' The REG_KEY function, that listens for the CA reply to the REG_KEY command message'''
        if msg == None: return False
        if (msg[ARGS][0]) == "T":
            cert = (msg[ARGS][1]).encode()
            self.cert = base64.b64decode(cert)
            self.waitingForCert.set()
            res = True
        else:
            print(colorama.Fore.RED+"ERR: CA was unable to register our key!"+colorama.Style.RESET_ALL)
            res =  False

        print( clilib.PROMPT, end="", flush=True )
        return res
    
    def shutdwn_con( self, recvNick : int ) -> bool:
            # peer shutdowm their socket peer with us, update our local dictionary to reflect that
                self.closeConn( recvNick, False )
                return True
    
    def reg_key( self ) -> bool:
        # find our CA ( the first CA we see if it exists )
        try:
            # see if we already have a cert from the CA
            if len(self.cert) > 1: 
                print( colorama.Fore.GREEN+"Our key has already been registered with the CA"+colorama.Style.RESET_ALL)
                return True
            
            keyStr = base64.b64encode( seclib.securityManager.serializePubKey( self.pubkey ) ).decode()
            # auto exchange keys with CA, if not already done
            if not self.keyring.has( self.nicknames[self.CA][self.URI] ):
                print( colorama.Fore.GREEN+"Auto-exchanging keys with CA!"+colorama.Style.RESET_ALL)
                self.xchng_key( self.CA )
                self.caKeyExchanged.wait(timeout=10) # wait for listen thread to process key exchange with CA and set this to true 
                if not self.caKeyExchanged.is_set():
                    print(colorama.Fore.RED+"ERR: Timed out waiting for CA response!"+colorama.Style.RESET_ALL)
                    return False
            # TODO: spin animation?
            self.sendMsg( self.CA, messageHandler.encode_message(Command.REG_KEY) )
            return True
        except CANotFound:
            print(colorama.Fore.RED+"ERR: No CA in our socketlist!"+colorama.Style.RESET_ALL)
        except:
            print(colorama.Fore.RED+"ERR: CA was unable to register our key!"+colorama.Style.RESET_ALL)
        return False
    
    def certExchange( self, nickname, msg : Union[Tuple[Command, List[str]], None] = None )->bool:
        # if init
        ourCert = ( base64.b64encode( self.cert ) ).decode()
        if msg == None:
            self.sendMsg( nickname, messageHandler.encode_message( Command.XCHNG_CERT, "R", ourCert) )
            return True
        elif msg[ARGS][0] == "R":
            if len(self.cert) <= 1: # if we don't have our own cert
                self.sendMsg( nickname, messageHandler.encode_message( Command.RECV_MSG, "Can't complete certExchange, I do not have a cert, aborting!" ) )
                return False 
            self.sendMsg( nickname, messageHandler.encode_message( Command.XCHNG_CERT, "S", ourCert ) )

            uri = self.nicknames[nickname][self.URI]
            cert = msg[ARGS][1]
            return self.check_key( uri, cert, nickname )
        elif msg[ARGS][0] == "S":
            cert = msg[ARGS][1]
            uri = self.nicknames[nickname][self.URI]
            return self.check_key( uri, cert,  nickname ) 
        # catch all for malformed args
        return False
    
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
        '''Turn a command and data into the encoded format [length of command + data]:[command]|[data1|data2]'''
        # Might need standard format for seperating arguments in the data field.
        contents: str = str(command.value) + ASEP
        for idx, arg in enumerate(args):
            contents += str( arg )
            if idx < len(args) - 1:
                contents += ASEP
        
        return ( str ( len ( contents ) ) + ":" + contents ).encode()
    
    @staticmethod
    def decode_message( message: bytes) -> Tuple[Command, list]:
        '''Turn the encoded format [length of command + data]:[command]|[data] into (command, data); Also checks the length'''
        m: str = message.decode()
        length: int = int(m.split(":", 1)[0])
        m = m.split(":", 1)[1]
        if len(m) != length:
            raise RuntimeError("Length of received message doesn't match expected length!")
        comm = Command(int(m.split(ASEP)[0]))
        args = m.split(ASEP)[1:]
        return comm, args


        
# script guard, things in this script don't run automatically when imported
if __name__ == "__main__":
    pass