import netlib
import sys
# multi-process, at least when in spawn mode( since Windows doesn't have forking ),
# requires a script guard, since spawn reimports modules
if __name__ == '__main__':
    name = sys.argv[0]
    peer = netlib.peer( name = name )
    peer.runLoop()
    print(f"Peer {name} closed")