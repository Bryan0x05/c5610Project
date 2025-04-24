import unittest
from libs.netlib import peer, messageHandler, Command
import time

SETNODE = ("python3", "nodeSetup.py")
# NOTE: setUp() func will run for every single test
class TestCases( unittest.TestCase ):

    @classmethod
    def setUpClass( cls ):
        ''' Runs once per class, setting up the test bed'''
        cls.peer1 = peer( name = "peer1", test = True, debug=True )
        cls.peer2 = peer( name = "peer2", test = True, debug=True )
        cls.peer1.start()
        cls.peer2.start()

    @classmethod
    def tearDownClass( cls ):
        '''Runs once per class, tearing down the test bed'''
        cls.peer1.shutDown()
        cls.peer2.shutDown()
    # set up a connection for each test
    def connHelper( self, p1 : peer, p2 : peer ):
        # step 1 of 3-way handshake, reach out and give our info
        self.assertTrue( p1.connectToIp( p2.ip, p2.port ), "handshake step 1 failed" )

        # step 2 of 3-way handshake, accept incoming and reply with our informaton on a new socket
        self.assertTrue(p2.acceptConn(), "handshake step2 failed")
        
        # step 3 of 3-way handshake, accept peer2's outboud socket to us.
        self.assertTrue( p1.acceptConn(), "handshake step3 failed")
        
        return True

    def msgHelper( self, sender : peer, recv : peer, msg : str ) -> bool:
        if not sender.sendMsg(1, messageHandler.encode_message(Command.SEND_MSG, msg) ) : return False
        time.sleep(1)
        readMsg = recv.checkForMsgs()
        self.assertFalse( readMsg == None, f"{sender.name}->{recv.name} comm failure!")
        # for tooling to realize readMsg cannot be none anymore
        if readMsg == None: return False
        readMsg = "".join(readMsg[0][1][0:])
        self.assertTrue( readMsg == msg, f"{sender.name}->{recv.name} message mismatch, recv : expected> { readMsg} : {msg}")
        return True
    
    def test_connection( self ):
        '''Monolithic basic netwokring test targetting setup, deconstruction and messaging.'''
        # SETUP peer1<->peer2
        self.connHelper( self.peer1, self.peer2 )
        # test peer1->peer2 socket pair, asserts are within.
        self.msgHelper( sender=self.peer1, recv=self.peer2, msg="hello peer 2")
        # test peer2->peer1 socket pair
        self.msgHelper( sender=self.peer2, recv=self.peer1, msg="hello peer 1")
        # close peer1 and peer2 sockets
        self.peer1.closeConn( 1, msgFlag=True )
        # run listen loop once, to read msg, and check its psuedo-switch statement logic
        self.peer2.listenCycle()
        time.sleep(1)
        self.assertTrue( len(self.peer1.nicknames) == len(self.peer2.nicknames) == 0, 
                        f"{self.peer1.nicknames} != {self.peer2.nicknames}" )
        self.peer1.conID = self.peer2.conID = 1


    def test_encrypted_msg( self ):
        ''' Monolithic test, testing key rings, CA, message en/de(decrpyt)'''
        self.connHelper( self.peer1, self.peer2 )
        # ! Consumes an extra sendMsg from the 3-way handshake ( might be an issue with the handsake sending an extra msg ? )
        msg = self.peer2.checkForMsgs()
        # ! The consumption only works if we check msg. Very odd beavior to look into later.
        if msg is None: return False
        self.peer1.xchng_key( 1 )
        time.sleep(1)
        # for for xnchng command
        msg = self.peer2.checkForMsgs()
        self.assertTrue( msg != None, "Failed to get xchng_key message")
        # for python to know msg is non-null pass this point
        if msg == None: return
        msg = msg[0]
        self.assertTrue( msg[self.peer1.COM] == Command.XCHNG_KEY, f"Expected exchange command not {msg[self.peer1.COM]}")
        self.peer2.xchng_key( 1, msg )
        time.sleep(1)
        # test encrypted peer1->peer2 socket pair with ENCYPTED msg
        self.msgHelper( sender=self.peer1, recv=self.peer2, msg="hello peer 2")
        # test encrypted peer2->peer1 socket pair with ENCYPTED msg
        self.msgHelper( sender=self.peer2, recv=self.peer1, msg="hello peer 1")
        # TODO: Add CA validation logic
        

def basicNetworkingSuite():
    suite = unittest.TestSuite()
    suite.addTest( TestCases("test_connection") )
    return suite

def encryptionSuite():
    suite = unittest.TestSuite()
    suite.addTest( TestCases("test_encrypted_msg") )
    return suite

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run( basicNetworkingSuite() )
    runner.run( encryptionSuite() )