# cs5610Project

## requirements
* Ubuntu LTS ==  20.04.6 
* Python == 3.8.10
* Python modules in requirements.txt ( pip install -r requirements.txt )
* Bash
* Tmux

## How to run
* 'bash tmuxSetup.sh' - Split terminal with a peer object + cmd shell per pane.
* 'help' to list availabe shell commands
* 'help cmd' to print command documentation
* 'cmd arg1 arg2...' to run a given command 
* 'tab' to auto-complete a command
*  up/down arrow to go through command history
*  enter, to repeat last output to terminal and newline.

## Using TMUX
Relevant hotkeys:
* C^b + arrow key - to switch between windows panes.
* C^b + d - deattaches the terminal ( tmuxSetup.sh will cleanup the session if it is unattached)