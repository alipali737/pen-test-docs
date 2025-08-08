```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

All of the methods in this page focus on further enumeration once a foothold has been gained, you must have already acquired any of the following:
- A domain user's cleartext password
- A NTLM password hash
- SYSTEM access on a domain-joined host

The https://wadcoms.github.io/ cheatsheet can be really helpful here.
## From Linux
### CrackMapExec
![[CrackMapExec#Summary]]
![[CrackMapExec#User Enumeration]]
![[CrackMapExec#Group Enumeration]]
![[CrackMapExec#Currently logged on users]]
![[CrackMapExec#List SMB Shares]]
![[CrackMapExec#Crawl a SMB share]]

### SMBMap
![[SMBMap#Summary]]
![[SMBMap#Check user's access to shares]]
![[SMBMap#Recursive list of a share]]
![[SMBMap#Recursive filename pattern search]]
![[SMBMap#File content searching]]

### RPCClient
![[SMB & RPC#MSRPC / RPCclient]]

### Impacket Toolkit
#### PSEXEC
 `psexec.py` is effectively a clone of the Sysinternals psexec executable but works slightly differently as its on linux. The tool works by:
 1. Uploading a randomly-named exe to the `ADMIN$` share on the target host
 2. It then registers the service via RPC and the Windows Service Control Manager.
 3. Once established, communication happens over a named pipe, providing a `SYSTEM` shell on the target host
This tool can be used to run system level powershell commands from the linux attack host.
```bash
psexec [domain]/[user]:'[pass]'@[ip]
```

#### WMIEXEC
`wmiexec.py` is similar to `psexec.py` but utilises a semi-interactive shell to execute commands through [[WMI]]. It doesn't drop files or executables on the target and generates fewer logs, *so its slightly more stealthy*. Unfortunately, it is likely to still be detected by modern EDR and anti-virus systems.
```bash
wmiexec [domain]/[user]:'[pass]'@[ip]
```
> It will create a lot of event ID: [4688: A new process has been created](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) as it creates a separate cmd.exe for each command run. This is normal in some orgs but could be a tip-off. It also runs under the context of the user, not `SYSTEM`.
### Windappsearch
![[Windapsearch#Summary]]
![[Windapsearch#Search for Domain Admins]]
![[Windapsearch#Search for Privileged Users]]

### Bloodhound
![[BloodHound#Summary]]
![[BloodHound#Collecting from Linux]]
