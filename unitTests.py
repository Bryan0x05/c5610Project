import unittest
import netlib
import time

SETNODE = ("python3", "nodeSetup.py")
# NOTE: setUp() func will run for every single test
# TODO: Create test suites to seperate encryption testing from base networking
class TestCases( unittest.TestCase ):

    @classmethod
    def setUpClass( cls ):
        ''' Runs once per class, setting up the test bed'''
        cls.peer1 = netlib.peer( name = "peer1", test = True, debug=True )
        cls.peer2 = netlib.peer( name = "peer2", test = True, debug=True )
        cls.peer1.start()
        cls.peer2.start()

    @classmethod
    def tearDownClass( cls ):
        '''Runs once per class, tearing down the test bed'''
        cls.peer1.shutDown()
        cls.peer2.shutDown()

    def test_connection( self ):
        '''Testing Connection setup and deconstruction'''
        # NOTE: Weirdness isloated to the unitTest. Peer2 should not be able to accept a connection, it never calls
        # acceptConn because of the test = true flag in its constructor yet here, it does.
        self.peer1.connectToIp( self.peer2.ip, self.peer2.port )
        time.sleep(2)
        self.assertTrue( self.peer1.outboundNicknames[1] == ( self.peer2.ip, self.peer2.port), "Nickname dict didn't populate correctly" )
        # NOTE: Testing sendMsg, behaves very odd in unitTest only. The caught expections cause it to exit for some reason.
        self.peer1.closeConn( 1 )
        self.assertTrue( len(self.peer1.outboundConns) == len(self.peer1.outboundNicknames) == 0 , "Dictionaries didn't de-populate" )

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