```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[Windapsearch](https://github.com/ropnop/windapsearch) is a python script that can be used to enumerate users, groups and computers in a Windows AD. It works by utilising LDAP queries to extract information.

## Installation
```bash
$ git clone https://github.com/ropnop/windapsearch.git

$ pip install python-ldap #or apt-get install python-ldap

$ ./windapsearch.py
```

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/ropnop/windapsearch
## Usage
### Enumerate users
```bash
python3 windapsearch.py --dc-ip [dc-ip] -u [user]@[domain] -p [pass] -U
```

### Query a group
```bash
python3 windapsearch.py --dc-ip [dc-ip] -u [user]@[domain] -p [pass] -m [group DN/CN]
```

### Search for computers
```bash
python3 windapsearch.py --dc-ip [dc-ip] -u [user]@[domain] -p [pass] -C -r
```
> the `-r` will perform a DNS lookup on each `dNSHostName` found. These results can be fed into other tools like [[Nmap]] and [[CrackMapExec]]. It is also an alternative way to find hosts without needed to do a port scan.

### Search for Domain Admins
```bash
python3 windapsearch.py --dc-ip [dc-ip] -u [user]@[domain] -p [pass] --da
```

### Search for Privileged Users
```bash
python3 windapsearch.py --dc-ip [dc-ip] -u [user]@[domain] -p [pass] --PU
```