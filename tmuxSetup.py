'''Setups a split terminal with 2 peer instances running'''
# NOTE: For Python <= 3.8.x, see tmuxSetup.sh instead
# TODO(maybe): backport to libtmux (0.38.1)
import libtmux
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

# Attachs the terminal to the session
server.attach_session( sessionName )

# Cleans up when the user detatches ( hotkey: c^b + d )
while True:
    time.sleep(1)
    isAttached = any( s.name == sessionName for s in server.attached_sessions )
    if isAttached:
        time.sleep(5)
    else:
        session.kill()
        break