
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
        # TODO Refactor or make a cleaner solution
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
        ''' prints the name of our peer'''
        print( self.peer.name )
        
    def do_quit( self, _ ):
        '''exits the shell & terminates client'''
        # Also see what happens in postcmd()
        self.peer.up = False
        return True
    
    def do_listSockets(self, _ ):
        '''Return the list of sockets '''
        pprint.pprint(self.peer.nicknames)
        
    def do_makeConn(self, line: str):
        ''' Connect to a given < ipAddr(x.x.x.x) > < port >'''
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
            if not self.peer.sendMsg( sockNick, self.msgHand.encode_message(self.com.RECV_MSG, msgSrc, msg) ):
                print(colorama.Fore.RED, f"ERR: Sending message to {sockNick} failed!" + colorama.Style.RESET_ALL)
            else:
                print(colorama.Fore.GREEN, "Message sent!" + colorama.Style.RESET_ALL)
        else:
            print(colorama.Fore.RED, f" ERR: Nickname {sockNick} is not an existing socket!" + colorama.Style.RESET_ALL )  
    
    def do_exchangeKeys( self, line : str ):
        ''' Exchange keys, and encrypt further messages with <target peer>'''
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
                print(colorama.Fore.GREEN, f"Exchange started with peer {sockNick}!" + colorama.Style.RESET_ALL)
        else:
            print(colorama.Fore.RED, f" ERR: Nickname {sockNick} is not an existing socket!" + colorama.Style.RESET_ALL )            
    
    def do_sendURIs( self, line : str ):
        ''' Inform the target peer of all nodes were connected to <peer nickname>'''
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
        ''' Ask the target peer, all the nodes it is connected to and aut-connected to them
            <peer nickname>'''
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
        ''' setPwd <none>, follow the prompts on screen to configure usr and pwd'''
        self.user = user = input( colorama.Fore.GREEN + "Set user name: " + colorama.Style.RESET_ALL )
        # gets pwd without echoing chars on the screen
        pwd : str = getpass.getpass( colorama.Fore.GREEN + "Set user pwd: " + colorama.Style.RESET_ALL )
        userPath = self.get_usr_path( user )
        os.makedirs(os.path.dirname(userPath), exist_ok=True)
        
        # store
        with open( userPath, 'wb') as handle:
            # TODO: 0 is human readable, likely should replace with non-humandable format in future.
            pickle.dump( (user, securityManager.encryptPwd( pwd, securityManager.getSalt() ) ), handle )
        # TODO: More pwd logic
        # - Be able to validate the create pwd was used
        # - Peers need support to spin up with an account attached
        
        # with open(f'{STOR}/{user}.pkl', 'rb') as handle:
        #        (Ruser,Rpwd) = pickle.load(handle)
                
    def do_info( self, _ ):
        '''info <none>, prints ip:port of our peer'''
        print(colorama.Fore.GREEN,f"{self.peer.ip}:{self.peer.port}" + colorama.Style.RESET_ALL)
    
    def do_getAttr( self, line ):
        try:
            args = line.split()
            name = args[0]
            print( self.peer.getAttr( name ) )
        except:
            self.default(line)

    def do_regKey( self, line):
        ''' Ask our CA(if existent) to certify our key and enable certify mode'''
        try:
            self.peer.reg_key()
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