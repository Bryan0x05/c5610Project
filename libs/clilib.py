
from libs.seclib import securityManager
import cmd
import colorama
import os
import pprint
import time
import getpass
import pickle

STOR = "./usrs"
PROMPT = "shell>"
class shell(cmd.Cmd):
    intro = "Type help to get started\n"
    
    prompt = PROMPT

    def __init__(self, peer, spin : bool = True ):
        super().__init__()
        # delayed import to avoid circular import
        import libs.netlib
        self.spin = spin
        self.user = None
        self.peer : libs.netlib.peer = peer
        self.msgHand =  libs.netlib.messageHandler
        self.com = libs.netlib.Command
        self.userPath = f"{STOR}/{{user}}.pkl"
    
    def get_usr_path(self, user):
        return self.userPath.format(user=user)
    
    def default( self, line ):
        '''Default behavior when command is not recongized'''
        print( colorama.Fore.RED, f"ERR: {line} is an unrecongized command or an incomplete argument" + colorama.Style.RESET_ALL)
    
    def do_clear( self, _):
        ''' Clear screen '''
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def do_name( self, _ ):
        '''name
        Description: Prints the URI of our peer, its unique global identifer in the network
        Arguments: None
        '''
        print( self.peer.name )
        
    def do_quit( self, _ ):
        '''quit
        Description: Closes both the listen and CLI threads of the our peer before gracefully exitting closing existing connections
            and signaling connected nodes that said connections rae closed. 
        Arguments: None
        '''
        # ! postcmd is called right after this and handles the termination and clean-up logic
        self.peer.up = False
        return True
    
    def do_listSockets(self, _ ):
        '''ListSockets
        Description: List all active socket connections in their integer nicknames (local node id)
        Arguments: None
        '''
        pprint.pprint(self.peer.nicknames)
        
    def do_makeConn(self, line: str):
        '''makeConn < ipAddr(x.x.x.x) > < port >
        Description: Attempts to connect peer to listening socket at provided ip:port
        Arguments:
            ipAddr (str): ipv4 address
            port (int): port number
        '''
        from libs.netlib import threadPlus
        try:
            args = line.split()
            ipAddr = args[0]
            port = int( args[1] )
        except:
            self.default(line)
            return
        spinThread = threadPlus( target = self.spinAnimation )
        # start spin animation
        spinThread.start()
        # Sends msg to local server to forward this message to the corresponding socket
        self.peer.knock( ipAddr, port)
        # signal spin animation to end
        spinThread.stop()
        # wait for thread to termiante
        spinThread.join()
        print("\n")
    
    def do_sendMsg(self, line : str ):
        '''sendMsg <socketnickname: int> <msg: str>
        Description: Sends a message to the given socket. This message can be unencrypted(default), encrypted but not certified, encrypted and certified.
            Exchanging keys (see "exchangeKeys" ) with a peer with switch the default for that connect to encrypted but not certified.
            Registering key ( see "regKey") gets a cert from a CA if one exists. If both peers exchangeKeys, have a cert they will automatically check-in with the
                CA to authenicate the key.
        Arguments:
            socketnickname (int): A local id for the outbound socket ( see "listsockets" for what's available )
            msg (str): A text message to send
        '''
        try:
            args = line.split()
            sockNick = int(args[0])
            msg = " ".join(args[1:])
        except:
            self.default( line )
            return
        if self.peer.nicknameExists( sockNick ):
            if not self.peer.sendMsg( sockNick, self.msgHand.encode_message(self.com.RECV_MSG, msg) ):
                print(colorama.Fore.RED, f"ERR: Sending message to {sockNick} failed!" + colorama.Style.RESET_ALL)
            else:
                print(colorama.Fore.GREEN, "Message sent!" + colorama.Style.RESET_ALL)
        else:
            print(colorama.Fore.RED, f" ERR: Nickname {sockNick} is not an existing socket!" + colorama.Style.RESET_ALL )  
    
    def do_exchangeKeys( self, line : str ):
        ''' Exchange keys < socket nickname : int>
        Description: Exchange keys with the local node id, if successful all further messages with that node are encrypted by default.
        Arguments:
            socketnickname (int): A local id for the outbound socket ( see "listsockets" for what's available )
        '''
        try:
            args = line.split()
            sockNick = int(args[0])
        except:
            self.default( line )
            return
        # TODO: look into this and confirm logic is correct
        if self.peer.nicknameExists( sockNick ):
            if not self.peer.xchng_key( sockNick ):
                print(colorama.Fore.RED, f"ERR: Exchanging with peer {sockNick} failed!" + colorama.Style.RESET_ALL)
            else:
                print(colorama.Fore.GREEN, f"Exchange started with node {sockNick}..." + colorama.Style.RESET_ALL)
        else:
            print(colorama.Fore.RED, f" ERR: Nickname {sockNick} is not an existing socket!" + colorama.Style.RESET_ALL )            
    
    def do_sendURIs( self, line : str ):
        ''' sendURIs < socknickname: int >
        Description: Get send all URIs (global node ids) from that we are connected to the provided node id, said node will auto-connect to those nodes.
        Arguments: socketnickname (int): A local id for the outbound socket ( see "listsockets" for what's available )
        '''
        try:
            args = line.split()
            sockNick = int(args[0])
        except:
            self.default( line )
            return
        if self.peer.nicknameExists( sockNick ):
            if not self.peer.sendConnURIs( sockNick ):
                print(colorama.Fore.RED, f"ERR: Sending URIs to {sockNick} failed!" + colorama.Style.RESET_ALL)
            else:
                print(colorama.Fore.GREEN, "URIs sent!" + colorama.Style.RESET_ALL)
        else:
            print(colorama.Fore.RED, f" ERR: Nickname {sockNick} is not an existing socket!" + colorama.Style.RESET_ALL )            
    
    def do_requestURIs( self, line : str ):
        ''' requestURIs < socknickname: int >
        Description: Get the URIs (global node ids) from the node id, and make our own direct connections to those nodes.
        Arguments: socketnickname (int): A local id for the outbound socket ( see "listsockets" for what's available )
        '''
        try:
            args = line.split()
            sockNick = int(args[0])
        except:
            self.default( line )
            return
        if self.peer.nicknameExists( sockNick ):
            if not self.peer.requestURIs( sockNick ):
                print(colorama.Fore.RED, f"ERR: Requesting URIs from {sockNick} failed!" + colorama.Style.RESET_ALL)
            else:
                print(colorama.Fore.GREEN, "URIs requested!" + colorama.Style.RESET_ALL)
        else:
            print(colorama.Fore.RED, f" ERR: Nickname {sockNick} is not an existing socket!" + colorama.Style.RESET_ALL )            

    def do_setPwd(self, _):
        ''' setPwd(depreciated command, passwords have been moved to future works)
            setPwd
            Description: Sets a username and pwd, and stores it securely with hash and salt.
                follow the prompts on screen to configure usr and pwd
            Arguments: None'''
        self.user = user = input( colorama.Fore.GREEN + "Set user name: " + colorama.Style.RESET_ALL )
        # gets pwd without echoing chars on the screen
        pwd : str = getpass.getpass( colorama.Fore.GREEN + "Set user pwd: " + colorama.Style.RESET_ALL )
        userPath = self.get_usr_path( user )
        os.makedirs(os.path.dirname(userPath), exist_ok=True)
        
        # store
        with open( userPath, 'wb') as handle:
            pickle.dump( (user, securityManager.encryptPwd( pwd, securityManager.getSalt() ) ), handle )
        # - Be able to validate the create pwd was used
        # - Peers need support to spin up with an account attached
        
        # with open(f'{STOR}/{user}.pkl', 'rb') as handle:
        #        (Ruser,Rpwd) = pickle.load(handle)
                
    def do_info( self, _ ):
        '''info
        Description: prints ip:port of our node's listening socket.
        Arguments: None'''
        print(colorama.Fore.GREEN,f"{self.peer.ip}:{self.peer.port}" + colorama.Style.RESET_ALL)
    
    def do_getAttr( self, line: str ):
        '''getAttr < attr : str>
        Description: A debug command, its a wrapper to print the peer object variable whose name matches the string to the CLI
        Arguments: attribute(str), the string should be a name that matches an existing attribute in peer.
            e.g. to see the value of peer.cert, type "getAttr cert" '''
        try:
            args = line.split()
            name = args[0]
            print( self.peer.getAttr( name ) )
        except:
            self.default(line)

    def do_regKey( self, line : str):
        ''' regKey
        Description: Find a CA in our socketlist and request them to grant us a certificate. If successful, we will enter certify mode, where we attempt to
            authenicate all future key exchanges, however it is dependent on a peer providing their own cert if any. This command only supports the existence of ONE CA in network.
        Arguments: None'''
        try:
            self.peer.reg_key()
        except:
            self.default(line)

    def do_checkKey(self, line : str):
        ''' checkKey < socknickname: int >
            Description: Exchange certs with the target no id, and then validate the incoming cert with our CA.
            Arguments: None
        '''
        # delayed import to prevent circular import
        from libs.netlib import CANotFound
        try:
            args = line.split()
            nickname = int( args[0] )
            ca = self.peer.CA
            if ca == nickname:
                print(colorama.Fore.RED, f"Cannot checkKey our own CA" + colorama.Style.RESET_ALL )
                return
            if len(self.peer.cert) == 0:
               print( colorama.Fore.GREEN+"No local cert on file, requesting one from the CA..."+colorama.Style.RESET_ALL)
               if not self.peer.reg_key(): 
                   print( colorama.Fore.RED +"Failed to send register key request to CA"+colorama.Style.RESET_ALL )
                   return
               
            self.peer.waitingForCert.wait( timeout = 10 )
            if  self.peer.waitingForCert.isSet() == False:       
                print( colorama.Fore.RED +"CA failed to generate a cert for us"+colorama.Style.RESET_ALL )
                return
            else:
                # we are now certified, with our local cert and now need to exchange with the target peer
                print( colorama.Fore.GREEN+"Starting cert exchange and validation, waiting..."+colorama.Style.RESET_ALL)
                self.peer.certExchange(  nickname )
                # TODO: finish this logic to re-actively check the cert of an existing connection
            # self.peer.check_key( uri, self.peer.CA )
        except CANotFound:
            print( colorama.Fore.RED +"No CA in our existing connections, please connect to a CA node first"+colorama.Style.RESET_ALL )
        except:
            self.default(line)
    
    def spinAnimation(self):
        if self.spin == False:
            return
        
        spinner = ['|', '/', '-', '\\']
        for symbol in spinner:
            print( colorama.Fore.GREEN + f'\r{symbol} Waiting...' + colorama.Style.RESET_ALL, 
                  end="", flush=True )
            time.sleep(0.5)

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
    
if __name__ == "__main__":
    pass