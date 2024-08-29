```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
A terminal multiplexer that can do a range of terminal utilities. This also has plugin support including a logging plugin.

## Installation
```
sudo apt install tmux -y
```

## Documentation
**Cheatsheet:** https://tmuxcheatsheet.com/
**Website:** https://github.com/tmux/tmux/wiki
## Usage
Start by entering `tmux` into a terminal. The default prefix key is `[CTRL + B]` with commands following the pattern: `[Prefix]` then `[Command Key(s)]`.
### Window Management
Create a new terminal window : `[CTRL + B]` + `[C]` (will list then at the bottom)
Switch between windows with : `[CTRL + B]` + `[window number]`

Vertically split windows : `[CTRL + B]` + `[SHIFT + %]`
	Switch with : `[CTRL + B]` + `[Up / Down]`
Horizontally split windows : `[CTRL + B]` + `[SHIFT + "]`
	Switch with : `[CTRL + B]` + `[Left / Right]`

### Plugin Management
1. Clone the [Tmux Plugin Manager](https://github.com/tmux-plugins/tpm) repo
`git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm`
2. Create a `.tmux.conf` in the home dir
3. Add the following content
```
## Set the history limit
set -g history-limit 100000

# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
```
4. Start a new tmux session `tmux new -s <session-name>`
5. Press `[Ctrl] + [B]` then `[Shift] + [I]` to install the plugin

### Logging
Once the logging plugin has been installed:
1. Start the logging with `[Ctrl] + [B]` and `[Shift] + [P]`
2. Stop the logging with `[Shift] + [P]` or `exit` (kills the session)

If you forget to start the logger, `[Ctrl] + [B]` then `[Alt] + [Shift] + [P]` captures the entire pane.

`[Ctrl] + [B]` & `[Alt] + [P]` captures a screenshot of the focused pane/window (useful when having multiple open)

