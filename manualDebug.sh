#!/bin/bash
# Script create a split terminal and start up peer objects
echo "Starting the script"

TMUX_SESSION_NAME='BTJ_NetSec'
TARGET_SCRIPT="setupNode.py"
# subproc flag, debug flag, CA flag
PEER_ARGS="F T F"
CA_ARGS="F T T"
tmux new-session -d -s $TMUX_SESSION_NAME >/dev/null
tmux new-window -t $TMUX_SESSION_NAME
tmux split-window -h -t $TMUX_SESSION_NAME
tmux split-window -h -t $TMUX_SESSION_NAME
# quoting these variables when using them perserves the spacing, which is a very important argument delimiter
tmux send-keys -t $TMUX_SESSION_NAME:1.0 "python3 "$TARGET_SCRIPT " " "$PEER_ARGS" Enter
tmux send-keys -t $TMUX_SESSION_NAME:1.1 "python3 "$TARGET_SCRIPT " " "$PEER_ARGS" Enter
tmux send-keys -t $TMUX_SESSION_NAME:1.2 "python3 "$TARGET_SCRIPT " " "$CA_ARGS" Enter
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