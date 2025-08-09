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

## From Windows
### ActiveDirectory PowerShell Module
> Using this module on a host, rather than dropping a tool in, can make us blend in more.

To see what modules are currently installed:
```PowerShell
Get-Module
```

To load the AD module:
```PowerShell
Import-Module ActiveDirectory
```
#### Get domain info
```PowerShell
Get-ADDomain
```
> this includes useful info such as: *domain SID*, *domain function level*, *child domains*, *name* etc
#### Get users (+ filter)
```PowerShell
Get-ADUser
```
If we want to filter for users that might be susceptible to Kerberoasting:
```PowerShell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipleName
```
#### Verify domain trust relationships
```PowerShell
Get-ADTrust -Filter *
```
> this lets us explore the trust relationships of various domains and child-domains the domain has
#### Group enumeration
```PowerShell
Get-ADGroup -Filter * | select name
```
We can then take these names and get specific information on particular ones:
```PowerShell
Get-ADGroup -Identity "[groupName]"
```
#### Group Membership
```PowerShell
Get-ADGroupMember -Identity "[groupName]"
```
> this will tell us who is in a particular group

### PowerView
[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) is a tool for PowerShell that serves to gain situational awareness in an AD environment. It provides similar information to BloodHound, providing ways to identify logged in users, enumerate domain information (eg. users, groups, ACLs, trusts), as well as perform file hunting and kerberoasting.
> it requires more manual effort to determine misconfigurations and relationships than a tool like [[BloodHound]] but can be very valuable still.

|**Command**|**Description**|
|---|---|
|`Export-PowerViewCSV`|Append results to a CSV file|
|`ConvertTo-SID`|Convert a User or group name to its SID value|
|`Get-DomainSPNTicket`|Requests the Kerberos ticket for a specified Service Principal Name (SPN) account|
|**Domain/LDAP Functions:**||
|`Get-Domain`|Will return the AD object for the current (or specified) domain|
|`Get-DomainController`|Return a list of the Domain Controllers for the specified domain|
|`Get-DomainUser`|Will return all users or specific user objects in AD|
|`Get-DomainComputer`|Will return all computers or specific computer objects in AD|
|`Get-DomainGroup`|Will return all groups or specific group objects in AD|
|`Get-DomainOU`|Search for all or specific OU objects in AD|
|`Find-InterestingDomainAcl`|Finds object ACLs in the domain with modification rights set to non-built in objects|
|`Get-DomainGroupMember`|Will return the members of a specific domain group|
|`Get-DomainFileServer`|Returns a list of servers likely functioning as file servers|
|`Get-DomainDFSShare`|Returns a list of all distributed file systems for the current (or specified) domain|
|**GPO Functions:**||
|`Get-DomainGPO`|Will return all GPOs or specific GPO objects in AD|
|`Get-DomainPolicy`|Returns the default domain policy or the domain controller policy for the current domain|
|**Computer Enumeration Functions:**||
|`Get-NetLocalGroup`|Enumerates local groups on the local or a remote machine|
|`Get-NetLocalGroupMember`|Enumerates members of a specific local group|
|`Get-NetShare`|Returns open shares on the local (or a remote) machine|
|`Get-NetSession`|Will return session information for the local (or a remote) machine|
|`Test-AdminAccess`|Tests if the current user has administrative access to the local (or a remote) machine|
|**Threaded 'Meta'-Functions:**||
|`Find-DomainUserLocation`|Finds machines where specific users are logged in|
|`Find-DomainShare`|Finds reachable shares on domain machines|
|`Find-InterestingDomainShareFile`|Searches for files matching specific criteria on readable shares in the domain|
|`Find-LocalAdminAccess`|Find machines on the local domain where the current user has local administrator access|
|**Domain Trust Functions:**||
|`Get-DomainTrust`|Returns domain trusts for the current domain or a specified domain|
|`Get-ForestTrust`|Returns all forest trusts for the current forest or a specified forest|
|`Get-DomainForeignUser`|Enumerates users who are in groups outside of the user's domain|
|`Get-DomainForeignGroupMember`|Enumerates groups with users outside of the group's domain and returns each foreign member|
|`Get-DomainTrustMapping`|Will enumerate all trusts for the current domain and any others seen.|
> This table doesn't contain everything, but has many valuable commands.

#### Get domain user info
```PowerShell
Get-DomainUser -Identity [user] -Domain [domain] | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```
#### Recursive Group Membership
Nested groups can be incredibly dangerous for privilege escalation, eg. if the group `SecAdmins` is a nested group to `Domain Admins` then anyone in the `SecAdmins` group would inherit domain admin permissions.
```PowerShell
Get-DomainGroupMember -Identity "[groupName]" -Recurse
```
> this will display all group members (including any nested groups and its members)
#### Trust Enumeration
```PowerShell
Get-DomainTrustMapping
```
> this shows us the domain trust relationships (like [[#Verify domain trust relationships]])
#### Testing for local administrator
```PowerShell
Test-AdminAccess -ComputerName [computerName]
```
> this will show us if our current user is an admin on the local machine. This can be really useful to test for many computers to see if we can access any other local administrators
#### Finding users who are vulnerable to Kerberoasting
The SPN attribute can suggest a user is vulnerable to kerberoasting, we can filter for this:
```PowerShell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipleName
```

### SharpView
This is a .NET port of PowerView (*as the original PV is officially deprecated, but still useful*). 
> SharpView can be really useful when PowerShell has been hardened or we need to try avoid it.
> This supports using `-Help` to see how to use a command
#### View a user
```PowerShell
.\SharpView.exe Get-DomainUser -Identity [user]
```

### Snaffler
[Snaffler](https://github.com/SnaffCon/Snaffler) is a tool for acquiring credentials or other sensitive data in an AD. It works by obtaining a list of hosts within the domain and then hunting for shares and readable directories. It iterates through any directories our user can read and hunts for files with sensitive information (*often by looking at its file extension*).

When setup correctly, SMB shares should:
- Require a user to be domain joined and required to authenticate when accessing the system.
- Permissions should ensure users can only access and see what is necessary for their daily role.

```cmd
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```
```PowerShell
.\Snaffler.exe -d [domain] -s -v data
```

### BloodHound
![[BloodHound#Summary]]
