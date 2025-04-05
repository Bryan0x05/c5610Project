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
        ''' Runs once per class, tearing down the test bed'''
        cls.peer1.shutDown()
        cls.peer2.shutDown()
        
    def test_testMakeConnection( self ):
        ''' Testing makeConn'''
        self.peer1.connectToIp( self.peer2.ip, self.peer2.port )
        time.sleep(2)
        ip, port = self.peer1.nicknames[1]
        self.assertTrue( ip == self.peer2.ip and port == self.peer2.port, "Socket information doesn't match peer2")

if __name__ == '__main__':
    unittest.main()