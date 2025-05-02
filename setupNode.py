''' A script uses by subprocess function calls to setup a peer object'''
import libs.netlib as netlib
import sys

if __name__ == '__main__':
    name = sys.argv[0]
    subProc = False if(  len(sys.argv) > 1 and sys.argv[1] == "F") else True
    debug = False if(  len(sys.argv) > 2 and sys.argv[2] == "F") else True
    isCA = True if(  len(sys.argv) > 3 and sys.argv[3] == "T") else False

    if not isCA:
        peer = netlib.peer( name = name, subProc=subProc, debug=debug)
        if subProc: 
            peer.runLoop()
        else: 
            peer.start()
        print(f"Peer {name} is now closed")
    else: # else isCA
        CA = netlib.CA( name = "CA" )
        CA.start()
        print(f"CA {name} is going down")