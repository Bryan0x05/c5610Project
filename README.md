# cs5610Project

## requirements
* Ubuntu LTS ==  20.04.6 
* Python == 3.8.10 ( NOTE: on the CS server this means using "python3" command and not "python" )
* Required Python modules are found requirements.txt or just "pip install -r requirements.txt"
* Bash shell
* Tmux

## How to run
* 'bash tmuxSetup.sh' - Starts a tmux server and splits terminal into 3 panes, 2 panes with peer objects and their own CLI 
and one CA that functions on a call and response paradigm.
* 'help' to list availabe shell commands
* 'help cmd' to documentation for the given command
* 'cmd arg1 arg2...' to run a given command
* 'tab' to auto-complete a command ( does not work with command arguments )
*  ↑ to go up command history
*  ↓ to go down command history
*  ctrl + u (C^u) to clear current line of input.
*  "enter", to repeat last output to terminal and new CLI prompt.

## Command Line(CLI) Primer
* info - prints out the current nodes URI which is ipAddr:port of the listening socket.
* makeConn - establishes a 2-way connection between nodes
* sendMsg - will send an plaintext msg by default, and any receiving peer will print out the msg to their commandline.
* exchangeKey - Once a connection is established, keys can be exchanged between nodes. Future communcation between nodes
will now be encrypted but not certified
* regKey - Gets a cert from the CA
* checkKey - exchanges certs between peers and requests validation of cert from the CA. If successful future messages are encrypted and certified.

### Notes
* Only 1 CA is supported at a given time in the network.

## TMUX Tips
Relevant hotkeys:
* C^b + arrow key - to switch between windows panes.
* C^b + [ - Allows the pane to be scrolled up or down. Press "q" to exit this mode.
* C^b + d - deattaches the terminal ( tmuxSetup.sh will cleanup the session if it is unattached by default)