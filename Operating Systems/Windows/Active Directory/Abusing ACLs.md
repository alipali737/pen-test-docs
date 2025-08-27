```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
![[Active Directory#Access Control List (ACL)]]
![[Active Directory#Access Control Entries (ACEs)]]
![[Active Directory#Discretional ACL (DACL)]]
![[Active Directory#System ACL (SACL)]]

## Key ACEs that can be abused
- [ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password#forcechangepassword) : Gives us the right to reset a user's password without knowing their original password (*best to tell the client before resetting passwords - they could be used for other purposes too*).
- [GenericWrite](https://bloodhound.specterops.io/resources/edges/generic-write#genericwrite) : This gives us rights to change/write any non-protected attribute on an object. Eg. we could add ourselves to a group, add an SPN to another user so we can [[Kerberoasting|kerberoast]] them.
- [AddSelf](https://bloodhound.specterops.io/resources/edges/add-self#addself) : Shows security groups that a user can add themselves too.
- [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all#genericall) : Grants full control over a target object. If we have access to a computer that is using [[Windows#Local Administrator Password Solution (LAPS)|LAPS]] then we can get access to the password and obtain local administrator.
![[Pasted image 20250826144004.png]]
## ACL Enumeration
We can enumerate the ACLs of a domain/system to potentially gain further internal access. This can be done with [[Credentialed Enumeration#PowerView|PowerView]] and [[BloodHound]].
### Find all domain objects a user controls
```PowerShell
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid [user]
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
> This gets all domain object ACLs, then matches the SecurityIdentifier field to the SID we provided.
> `-ResolveGUIDs` ensures that the ACL types are in a human readable formate rather than their GUIDs
#### Performing this without PowerView
> [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps)
> [Get-Acl](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.2)

**Create a list of domain users**
```PowerShell
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

**Get ACL information for each user**
```PowerShell
foreach($line in [System.IO.File]::ReadLines("<domain_users>")) {get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\<target_user>'}}
```

**Manually resolve the ObjectType GUID**
```PowerShell
$guid = "<guid>"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,DistinguishedName,rightsGuid | ? {$_.rightsGuid -eq $guid} | fl
```
