```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Inveigh is the Windows equivalent tool for [[Responder]], it hosts support for IPv4 & IPv6 and several protocols eg:
- [[LLMNR]]
- [[DNS]]
- [[SMB & RPC|NBT-NS]]
- DHCP
- ICMP
- HTTP(S)
- [[SMB & RPC|SMB]]
- [[LDAP]]

It has two forms:
- Legacy PowerShell version (Inveigh)
- Preferred C# rebuild (InveighZero)

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/Kevin-Robertson/Inveigh
## Usage
```Powershell
PS> .\Inveigh.exe -?
```
### Interactive Console
- Pressing `Esc` will enter the interactive console
- From there the `HELP` command will display all options eg. `GET NTLMV2UNIQUE` gets a NTLMv2 hash per user