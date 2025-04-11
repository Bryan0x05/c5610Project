.#!/bin/bash
# Script create a split terminal and start up peer objects
echo "Starting the script"

TMUX_SESSION_NAME='BTJ_NetSec'
TARGET_SCRIPT="setupNode.py"
ARGS="F"
tmux new-session -d -s $TMUX_SESSION_NAME >/dev/null
tmux new-window -t $TMUX_SESSION_NAME
tmux split-window -h -t $TMUX_SESSION_NAME
tmux send-keys -t $TMUX_SESSION_NAME:1.0 "python3 "$TARGET_SCRIPT " " $ARGS Enter
tmux send-keys -t $TMUX_SESSION_NAME:1.1 "python3 "$TARGET_SCRIPT " " $ARGS Enter
tmux attach -t $TMUX_SESSION_NAME

output="1"
# Loop every 2 seconds while our tmux session has an attached terminal
while [[ -n "$output" ]]; do
 output=$(tmux ls | grep $TMUX_SESSION_NAME.*attached)
 sleep 2
done

# Clean the unattached tmux session, NOTE: Uncomment this if you want to manually manage it
tmux kill-session -t $TMUX_SESSION_NAME

exit 0