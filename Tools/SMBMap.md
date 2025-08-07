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
>For many of the commands, a domain doesn't have to be provided if you aren't in an AD environment.
### Check user's access to shares
```bash
smbmap -u [user] -p [pass] -d [domain] -H [ip]
```
> Can be pointed at a domain controller for AD
### Recursive list of a share
```bash
# Dirs & Files listed
smbmap -u [user] -p [pass] -d [domain] -H [ip] -R '[shareName]'

# Directories only
smbmap -u [user] -p [pass] -d [domain] -H [ip] -R '[shareName]' --dir-only
```

### Non-recursive list of a share's root
```bash
smbmap -u [user] -p [pass] -d [domain] -H [ip] -r '[shareName]' -q
```

### Recursive filename pattern search
```bash
smbmap -u [user] -p [pass] -d [domain] -H [ip] -R '[shareName]' -A '([pattern])'
smbmap -u [user] -p [pass] -d [domain] -H [ip] -R '[shareName]' -A '(password|config)'
```

### File content searching
```bash
smbmap -u [user] -p [pass] -d [domain] -H [ip] -F '[pattern]'
smbmap -u [user] -p [pass] -d [domain] -H [ip] -F '[1-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]'
```

### Get host version info
```bash
smbmap --host-file [hosts] -v
```

### Command Execution
```bash
smbmap -u [user] -p [pass] -d [domain] -H [ip] -x '[cmd]'
```