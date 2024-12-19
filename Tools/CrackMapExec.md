```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
A post-exploitation tool for assessing the security of *large Active Directory networks*. CME supports a number of protocols: [[MSSQL]], [[SMB]], [[SSH]], [[WinRM]] etc (can be listed in the help section of the CLI). With this tool we can also brute force user credentials with dictionary attacks. Once we have access we can use a tool like [[Evil-Winrm]] to efficiently communicate with the winrm service.

> A community open-source version is [NetExec](https://github.com/Pennyw0rth/NetExec) which is based on the original CME by its original contributors

## Installation
```
sudo apt-get -y install crackmapexec
```

## Documentation
**Cheatsheet:** 
**Website:** https://web.archive.org/web/20231116172005/https://www.crackmapexec.wiki/
## Usage
```sh
crackmapexec <proto> <target-ip> -u <user or userlist> -p <pass or passlist>
```

### List SMB Shares
```sh
crackmapexec smb [ip] -u [user] -p [pass] --shares
```