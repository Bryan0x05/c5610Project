# cs5610Project

## requirements
* Python >= 3.8.1
* Tmux

## How to run
* 'bash tmuxSetup.sh' - Split terminal with a peer object + cmd shell per pane.
* 'help' to list availabe shell commands
* 'help cmd' to print command documentation
* 'cmd arg1 arg2...' to run a given command 

## Using TMUX
Relevant hotkeys:
* C^b + arrow key - to switch between windows panes.
* C^b + d - deattaches the terminal ( tmuxSetup.sh will cleanup the session if it is unattached)