''' A script uses by subprocess function calls & bash scripts to setup a peer object'''
import libs.netlib as netlib
import sys

if __name__ == '__main__':
    name = sys.argv[4]
    # Starts a subProc peer that is who's input and output is redirected to handles in a higher level peer object
    # This is primarily used for testing
    subProc = False if(  len(sys.argv) > 1 and sys.argv[1] == "F") else True
    # enable or disable debug prints
    debug = False if(  len(sys.argv) > 2 and sys.argv[2] == "F") else True
    # If we are launching a CA instead
    isCA = True if(  len(sys.argv) > 3 and sys.argv[3] == "T") else False

    if not isCA:
        peer = netlib.peer( name = name, subProc=subProc, debug=debug)
        if subProc: 
            peer.runLoop()
        else: 
            peer.start()
        print(f"Peer {name} is now closed")
    else: # else isCA
        CA = netlib.CA( name = "CA", debug=debug )
        CA.start()
        print(f"CA {name} is going down")