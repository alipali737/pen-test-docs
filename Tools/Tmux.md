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
