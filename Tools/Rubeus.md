```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Rebeus is a tool for interacting with raw kerberos. It can make general interactions but also attacks, boasting a vast number of options and configuration settings.

Some key features include:
- Performing kerberoasting and outputting hashes to a file
- Using alternative credentials
- Performing kerberoasting followed by a [[Password Attacks#Pass-the-Hash|pass-the-hash]] attack
- Performing "opsec" kerberoasting to filter out AES-enabled accounts
- Requesting tickets for accounts passwords set between a specific date range
- Placing a limit on the number of tickets requested
- Performing AES kerberoasting

## Installation
```

```

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/GhostPack/Rubeus
## Usage
### Kerberoast accounts that have admin
```PowerShell
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```