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

    def test_connection( self ):
        '''Testing Connection setup and deconstruction'''
        
        self.peer1.connectToIp( self.peer2.ip, self.peer2.port )
        self.peer2.acceptConn()
        peer1Msg = "hello peer 2"
        self.peer1.sendMsg(1, messageHandler.encode_message(Command.SEND_MSG, peer1Msg) )
        time.sleep(1)
        readMsg = self.peer2.checkForMsgs()
        self.assertFalse( readMsg == None, "read msg is none!")
        if readMsg == None: return
        readMsg = "".join(readMsg[0][1][0:])
        self.assertTrue( readMsg == peer1Msg, f"message mismatch, read msg : expected> { readMsg} : {peer1Msg}")
        # test 2-way comm
        peer2Msg = "hello peer 1"
        self.peer2.sendMsg(1, messageHandler.encode_message(Command.SEND_MSG, peer2Msg) )
        readMsg = self.peer2.checkForMsgs()
        if readMsg == None: return
        readMsg = "".join(readMsg[0][1][0:])
        self.assertTrue( readMsg == peer2Msg, f"message mismatch, read msg : expected> { readMsg} : {peer1Msg}")

def basicNetworkingSuite():
    suite = unittest.TestSuite()
    suite.addTest( TestCases("test_connection") )
    return suite

def encryptionSuite():
    suite = unittest.TestSuite()
    # TODO: Add the tests
    return suite

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run( basicNetworkingSuite() )