import netlib
import sys
# multi-process, at least when in spawn mode( since Windows doesn't have forking ),
# requires a script guard, since spawn reimports modules
if __name__ == '__main__':
    name = sys.argv[0]

    subProc = False if(  len(sys.argv) > 1 and sys.argv[1] == "F") else True
    peer = netlib.peer( name = name, subProc=subProc)
    if subProc: 
        print("subproc true")
        peer.runLoop()
    else: 
        print("subproc false")
        peer.start()
    print(f"Peer {name} closed")