''' One subprocess node, one direct to our terminal both under manual control'''
import netlib
import multiprocessing
import time
import subprocess
import os
import pty
# multi-process, at least when in spawn mode( since Windows doesn't have forking ),
# requires a script guard, since spawn reimports modules
if __name__ == '__main__':
    SETNODE = ("python3", "setupNode.py")
    # file descritors like in C, where an int represents a comm channel
    masterFd, servantFd = pty.openpty()
    
    peer1 = netlib.peer( port = 61444, name="peer1", debug=True, subProc = False )
    peer2 = netlib.peer( port = 61454, name="peer2", debug=True, subProc = True)
    
    peer2.start()
    print(f"peer 2 information: {peer2.ip}:{peer2.port}")
    
    peer1.start()
    print("peer 1 dead")
    
    peer2.sendCommand("quit")
    print("peer 2 dead")
