```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Useful Tools
- [Seatbelt](https://github.com/GhostPack/Seatbelt) : C# project for local priv esc checks
- [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) : windows version of PEAS for priv esc checks
- [PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1) : Focuses on finding misconfigurations and can do some exploits
- [SharpUp](https://github.com/GhostPack/SharpUp) : C# version of PowerUp
- [JAWS](https://github.com/411Hall/JAWS) : PS script for enumerating priv esc vectors (written in PS 2.0)
- [SessionGopher](https://github.com/Arvanaghi/SessionGopher) : finds and decrypts any saved sessions for remote access tool (eg. RDP, filezilla, putty)
- [Watson](https://github.com/rasta-mouse/Watson) : .NET tool for enumerating missing KBs and suggesting exploit vectors
- [LaZagne](https://github.com/AlessandroZ/LaZagne) : Password retriever
- [Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng) : uses `systeminfo` utility to suggest OS exploits
- [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) : Built in tools such as `AccessChk`, `PipeList`, and `PsService` can all be used for enumeration

## Situational Awareness
### Network Information
- Interface(s), IP Address(es), DNS Information : `ipconfig /all`
- [[Network Addressing#Address Resolution Protocol (ARP)|ARP Cache]] : `arp -a`
- [[Network Addressing#Routing Tables|Routing Table]] : `route print`

### Protections
- See Windows Defender status : `Get-MpComputerStatus`
- List AppLocker Rules : `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`
- Test AppLocker Policy : `Get-AppLockerPolicy -Local | Test-AppLockerpolicy -path C:\Windows\System32\cmd.exe -User Everyone`
