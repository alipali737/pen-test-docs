```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
The metasploit framework contains a ton of modules for public exploits and useful pen testing utilities.

## Installation
```
sudo apt install metasploit -y
```

## Documentation
**Cheatsheet:** 
**Website:** 
## Usage
### Initialise the msf console
```
msfconsole
```

### Searching
```
search [filters] [name]
search exploit eternalblue
search openssh
search cve:2009 type:exploit vsftpd
```

### Using an exploit
```
use [path/to/module]
```

### Configuring a module
```
show options

set [OPTION] [value]
set RHOSTS 10.0.9.4
```

### Running an exploit
```
run

check (used to check if the target is vulnerable before exploiting)

exploit
```