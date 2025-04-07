import libtmux
import libtmux.constants
import time

server = libtmux.Server()
sessionName = "peer2peer_tmux"

session = server.sessions.get( sessionName = sessionName, default=None )
if session != None:
    session.kill_session()
else:
    session = server.new_session(session_name=sessionName, kill_session=True)
    print(f"Created session '{sessionName}'.")

window = session.active_window

# Split horizontally
pane1 = window.split(attach=False)
for pane in window.panes:
    pane.send_keys("python3 setupNode.py F")

server.attach_session( sessionName )

while True:
    time.sleep(1)
    isAttached = any( s.name == sessionName for s in server.attached_sessions )
    if isAttached:
        time.sleep(5)
    else:
        session.kill()
        break