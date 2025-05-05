#!/bin/bash
# ====================
# Setups a tmux server with 3 panes

# Left and center panes, are their own processes with a multi-thread peer object.
# Each peer object has a listen thread to act as a server and CLI thread. The "shell>" shows
# that the CLI is active and accepting input.

# The rightmost pane, starts up a CA instance. The CA only does call and responds and has no attached CLI.
# ====================
echo "Starting the script"

TMUX_SESSION_NAME='BTJ_NetSec'
TARGET_SCRIPT="setupNode.py"
# subproc flag, debug flag, CA flag
PEER_ARGS="F F F"
CA_ARGS="F F T"
tmux new-session -d -s $TMUX_SESSION_NAME >/dev/null
tmux new-window -t $TMUX_SESSION_NAME
tmux split-window -h -t $TMUX_SESSION_NAME
tmux split-window -h -t $TMUX_SESSION_NAME
# quoting these variables when using them perserves the spacing, which is a very important argument delimiter
tmux send-keys -t $TMUX_SESSION_NAME:1.0 "python3 "$TARGET_SCRIPT " " "$PEER_ARGS" " " "peer1" Enter
tmux send-keys -t $TMUX_SESSION_NAME:1.1 "python3 "$TARGET_SCRIPT " " "$PEER_ARGS" " " "peer2" Enter
tmux send-keys -t $TMUX_SESSION_NAME:1.2 "python3 "$TARGET_SCRIPT " " "$CA_ARGS" " " "CA" Enter
tmux attach -t $TMUX_SESSION_NAME

output="1"
# Loop every 2 seconds while our tmux session check has an attached terminal
while [[ -n "$output" ]]; do
 output=$(tmux ls | grep $TMUX_SESSION_NAME.*attached)
 sleep 2
done

# Clean the unattached tmux session, NOTE: Uncomment this if you want to manually manage it
tmux kill-session -t $TMUX_SESSION_NAME

exit 0 