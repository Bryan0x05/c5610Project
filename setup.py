import netlib
import multiprocessing
import time
import os
import subprocess
# multi-process, at least when in spawn mode( since Windows doesn't have forking ),
# requires a script guard, since spawn reimports modules
if __name__ == '__main__':
    PY = "python3"
    peer1 = netlib.peer( port = 65535 )
    
    # create shell, shell then runs peer2
    subprocess.Popen([ PY, "nodeSetup.py", f"{peer1.getMyIpAddr()}","65525"], text=False )
    # cProc = multiprocessing.Process( target = client.runLoop )
    
    # start procs
    # p2Proc.start()
    # cProc.start()
    # give time for server to spin up
    time.sleep(1)
    # cmdloop() had stdin issues running a new process
    peer1.runLoop()
    # wait until procs are finished
    print("Waiting for peer2 to go down...")
    # p2proc.join()
    # cProc.join()

    print("Multi-process test done!")