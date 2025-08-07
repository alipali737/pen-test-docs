```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[SMBMap](https://github.com/ShawnDEvans/smbmap) is a tool for enumerating SMB shares from a Linux attack host. It can gather listings, permissions, and share contents. With appropriate access, it can download and upload files, alongside executing remote commands.

## Installation
```bash
sudo pip3 install smbmap
```

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/ShawnDEvans/smbmap
## Usage
### Check user's access to shares
```bash
smbmap -u [user] -p [pass] -d [domain] -H [ip]
```
> Can be pointed at a domain controller for AD