```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Vim* is the upgraded version of *vi*. It is a text editor that can be completely controlled by the keyboard. It is useful for editing files on remote linux systems. It also has extensions and plugins.

## Installation
```
Installed by default on most linux systems
```

## Documentation
**Cheatsheet:** https://vimsheet.com/
**Website:** 
## Usage
### Normal Mode
This mode is what opens by default and is read-only, the following keys can be used:
- `x` : cut character
- `dw` : cut word
- `dd` : cut full line
- `yw` : copy word
- `yy` : copy full line
- `p` : paste
These can be prefixed with a number to perform the action multiple times, eg. `4yw` will copy 4 words.

### Insert Mode
Pressing `i` will enter insert mode which allows you to write and edit the file. Press `esc` to return back to normal mode.

### Command Mode
Pressing `:` will enter command mode at the bottom of the window:
- `:1` : go to line 1
- `:w` : write the file (save)
- `:q` : quit (will prompt to save)
- `:q!` : quit (without saving)
- `:wq` : write and quit