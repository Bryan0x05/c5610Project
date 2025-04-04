import netlib
import sys

if __name__ == '__main__':
    PY = "python3"
    ipAddr = sys.argv[1]
    port = int( sys.argv[2] )
    peer = netlib.peer( port )
    peer.connectToIp( ipAddr, port )
    peer.runLoop()
    # wait until procs are finished
    print(f"Waiting for peer2 on port: {ipAddr}:{port} to go down...")