import netlib
import multiprocessing
import time
# multi-process, at least when in spawn mode( since Windows doesn't have forking ),
# requires a script guard, since spawn reimports modules
if __name__ == '__main__':
    server = netlib.server( port = 65535 )
    client = netlib.client( port = 65525, sInfo=( server.getMyIpAddr(), 65535 ) )

    
    # create procs
    sProc = multiprocessing.Process( target = server.runLoop )
    # cProc = multiprocessing.Process( target = client.runLoop )

    # start procs
    sProc.start()
    # cProc.start()
    
    time.sleep(1)
    # cmdloop() had stdin issues running a new process
    client.runLoop()
    # wait until procs are finished
    sProc.join()
    # cProc.join()

    print("Multi-process test done!")