''' A script uses by subprocess function calls to setup a peer object'''
import libs.netlib as netlib
import sys

if __name__ == '__main__':
    name = sys.argv[0]
    subProc = False if(  len(sys.argv) > 1 and sys.argv[1] == "F") else True
    debug = False if(  len(sys.argv) > 2 and sys.argv[2] == "F") else True

    peer = netlib.peer( name = name, subProc=subProc, debug=debug)
    if subProc: 
        peer.runLoop()
    else: 
        peer.start()
    print(f"Peer {name} is now closed")