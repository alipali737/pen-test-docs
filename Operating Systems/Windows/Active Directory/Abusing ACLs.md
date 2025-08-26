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