import unittest
import netlib
import time
import sys

SETNODE = ("python3", "nodeSetup.py")
# NOTE: setUp() func will run for every single test
# TODO: Create test suites to seperate encryption testing from base networking
class TestCases( unittest.TestCase ):

    @classmethod
    def setUpClass( cls ):
        ''' Runs once per class, setting up the test bed'''
        cls.peer1 = netlib.peer( name = "peer1", test = True, debug=True )
        cls.peer2 = netlib.peer( name = "peer2", subProc = True, debug=True )
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
        time.sleep(2)
        self.assertTrue( self.peer1.nicknames[1] == ( self.peer2.ip, self.peer2.port), "Nickname dict didn't populate correctly" )

        ip, port = self.peer1.nicknames[1]
        self.assertTrue( ip == self.peer2.ip and port == self.peer2.port, "Socket information doesn't match peer2")

        # NOTE: peer2.sendCommand sends a command to a third peer object that's running a subprocess
        # as a result it doesn't have access to the same information as peer2. So:
        # TODO: Shared memory structure to sync the 2 peer objects? Or a simplier scheme

        # sendMsg = "Hello Peer 1"
        # self.peer2.sendCommand( f"sendMsg 1 {sendMsg}" )
        # rcvMsg = self.peer1.checkForMsgs()
        # self.assertTrue( sendMsg == rcvMsg, f"sendMsg != {rcvMsg}" )

        self.peer1.closeConn( 1 )
        self.assertTrue( len(self.peer1.connections) == len(self.peer1.nicknames) == 0 , "Dictionaries didn't de-populate" )
    
    
if __name__ == '__main__':
    unittest.main()