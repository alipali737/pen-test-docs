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
- [Juicy Potato](https://github.com/ohpe/juicy-potato) : utilises `SeImpersonate` or `SeAssignPrimaryToken` privileges to escalate

## Situational Awareness
### Network Information
- Interface(s), IP Address(es), DNS Information : `ipconfig /all`
- [[Network Addressing#Address Resolution Protocol (ARP)|ARP Cache]] : `arp -a`
- [[Network Addressing#Routing Tables|Routing Table]] : `route print`

### Protections
- See Windows Defender status : `Get-MpComputerStatus`
- List AppLocker Rules : `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`
- Test AppLocker Policy : `Get-AppLockerPolicy -Local | Test-AppLockerpolicy -path C:\Windows\System32\cmd.exe -User Everyone`

### Key Data Points
- **OS name** will tell us where tools we can expect to be available (eg. Windows 10, Server 2019)
- **OS version** could inform us if any public exploits are known for that version
- **Running Services** will give us an idea on what to focus on, especially ones owned by higher privilege contexts

### System Information
- Running processes : `tasklist /svc` (*its important to be familiar with [Session Manager Subsystem (smss.exe)](https://en.wikipedia.org/wiki/Session_Manager_Subsystem), [Client Server Runtime Subsystem (csrss.exe)](https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem), [WinLogon (winlogon.exe)](https://en.wikipedia.org/wiki/Winlogon), [Local Security Authority Subsystem Service (LSASS)](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service), and [Service Host (svchost.exe)](https://en.wikipedia.org/wiki/Svchost.exe), as it will allow us to filter out standard processes and look for non-standard ones*)
- Env Vars : `set` (`PATH` is a particularly interesting one to look at.)
- `systeminfo`:
	- The KBs under `HostFixes` can reveal when it was last patched (*can be hidden from non-admins though*)
	- Boot time and OS version could also give us an idea of the patch level (*if its not restarted in ages, its likely not be patched*)
	- Can also see if its a VM too
- If hotfixes can't be seen in the `systeminfo`, WMI might be able to view it with `wmic qfe` or PS (`Get-HotFix | ft -AutoSize`)
- Installed Programes : `wmic product get name` or `Get-WmiObject -Class Win32_product | select Name, Version`
- Active TCP & UDP connections : `netstat -ano`

### User & Group Information
- Logged in users : `query user`
- Current User : `echo %USERNAME%` / `whoami`
- Current user privs : `whoami /priv`
- Current user group info : `whoami /groups`
- Get all users : `net user`
- Get all groups : `net localgroup`
- Group info : `net localgroup [group]`
- Pass policy & other account info : `net accounts`
- 