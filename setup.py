import multiprocessing.process
import netlib
import multiprocessing

# multi-process, at least when in spawn mode( since Windows doesn't have forking ),
# requires a script guard, since spawn reimports modules
if __name__ == '__main__':
    server = netlib.server( port = 65535 )
    client = netlib.client( port = 65525 )
    # create procs
    sProc = multiprocessing.Process( target = server.runLoop() )
    cProc = multiprocessing.Process( target = client.runLoop() )

    # start procs
    sProc.start()
    cProc.start()

    # wait until procs are finished
    sProc.join()
    cProc.join()

    print("Multi-process test done!")
