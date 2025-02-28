```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

A directory service for windows network environments. Provides centralised management of resources, users, devices etc. It provides *authentication*, *accounting*, and *authorization* functions within an enterprise Windows environment.

AD was first released with Windows Server 2000 and has been improved incrementally since. It is based on the `x.500` and `LDAP` protocols (*still using them in some capacity to this day*). It is designed to be *backwards compatible* and many features are arguably not "secure by default".

It's essentially a read-only database that *any user* (regardless of privilege) can enumerate, meaning it can be searched for potentially exploitable misconfigurations. It is extremely important to properly secure an AD implementation (network segmentation, least privilege, hardening etc), many attacks can be done as a standard domain user account.

## Active Directory Structure
AD is a hierarchical tree structure, with a forest a the top containing one or more domains, these can then have nested subdomains.

A very simplistic high level structure for an AD may look like:
```
INLANEFREIGHT.LOCAL/       <-- Forest
├── ADMIN.INLANEFREIGHT.LOCAL  <-- Tree
│   ├── GPOs
│   └── OU  <-- Organisational Unit
│       └── EMPLOYEES      <-- Container
│           ├── COMPUTERS
│           │   └── FILE01     <-- Leaf
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

### Forests (Root Domains)
Forests are the top level element of the AD structure, forests can:
- Contain multiple domains
- Include child/sub domains
- Control all objects under its security boundary
Forests are a domain structure within which contained objects (users, computers, and groups) are accessible. It has many built-in Organisational Units (OUs), such as *Domain Controllers*, *Users*, *Computers*, and new OUs can be created as required. OUs can contain objects and sub-OUs, allowing for the assignment of different group policies.

It is common to see multiple domains (or forests) linked together via a *trust relationship* in organisations that perform a lot of acquisitions. It is often quicker and easier to create a trust relationship with another domain/forest than recreate all the objects in the current domain.

![[Pasted image 20250228100259.png|800]]
> This is an example of a trust relationship between two domains. This means that any users in either `inlanefrieght.local` or `freightlogistics.local` can access any of the sub domains below either one. True
> HOWEVER, if a user lower down in the chain, eg. `admin.dev.inlanefrieght.local` was created, they would NOT be able to access anything else (even within the same domain) as you can only access down the tree. If you wanted to access `wh.corp.inlanefreight.local` for example, a trust relationship would need to be setup between them. 

### Objects
Any resource present in an AD environment, eg. OUs, printers, users, domain controllers are all Objects

### Attributes
Every object in an AD has an associated set of [attributes](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all) used to define its characteristics. Eg. the computer object has attributes such as hostname and DNS name.

### Schema
The AD [schema](https://docs.microsoft.com/en-us/windows/win32/ad/schema) is essentially the blueprint for any enterprise environment. It defines what types of objects and their associated attributes exist. It holds definitions for AD objects and holds the information for each object. Eg. user objects in the AD belong to the *users* class in the schema.

### Tree
A collection of AD domains that begins at a single root domain. A forest is a collection of trees. Eg. `dev.inlanefrieght.local-->admin.dev.inlanefreight.local` is a tree, and `inlanefreight.local` is the forest as it is the root.

### Container
Container objects hold other objects and have a defined place in the directory subtree hierarchy.

### Leaf
Leaf objects do not contain other objects and are found at the end of the subtree

## Terminology 

### Global Unique Identifier (GUID)
A 128-bit value assigned when a domain object is created. It is unique across the enterprise, similar to a MAC address. It is stored in the *objectGUID* attribute.

### Security Principals
[Security principals](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals) are anything that the operating system can authenticate, including users, computer accounts, or processes that run as a user. In AD, security prinipals are domain objects that manage access to other resources in the domain. [[Windows#Security Account Manager (SAM)|SAM]] can be used to manage local user accounts and security groups on a single computer but this won't be AD managed then.

### Security Identifier (SID)
A [[Windows#Security Identifier (SID)|SID]] is a unique identifier for a security principal or security group. In AD, it is issued by the domain controller. It is contained within the authentication token received by a user when they log in. It is then used to check access rights. [well-known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) are used to identify generic users and groups.

### Distinguished Name (DN)
A [Distinguished Name (DN)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names) describes the full path to an object in AD (`cn=jsmith, ou=IT, ou=Employees, dc=inlanefreight, dc=local` is effectively `inlanefrieght.local/Employees+IT/jsmith`). *Its LDAP*.

### Relative Distinguished Name (RDN)
A [Relative Distinguished Name (RDN)](https://docs.microsoft.com/en-us/windows/win32/ad/object-names-and-identities) is a single component of the DN that identifies the object as unique from other objets at the current level. Eg. `jsmith` is the RDN of the object. The RDN must be unique in an OU.

### sAMAccountName
The [sAMAccountName](https://docs.microsoft.com/en-us/windows/win32/ad/naming-properties#samaccountname) attribute is the user's logon name. It must be unique and <= 20 chars.

### userPrincipleName
The [userPrincipalName](https://social.technet.microsoft.com/wiki/contents/articles/52250.active-directory-user-principal-name.aspx) attribute is the `<user-account-name>@<domain-name>` : `jsmith@inlanefreight.local` (*it is not mandatory*)

### FSMO Roles
[Flexible Single Master Operation (FSMO)](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles) roles give Domain Controllers (DC)s the ability to continue authenticating users and granting permissions without interruption. All 5 roles are assigned to the first DC in the forest root domain in a new AD forest. Each time a new domain is added, on the RID Master, PDC Emulator and Infrastructure Master roles are assigned to the new domain. FSMO roles are typically set when domain controllers are created, but sysadmins can transfer these roles if needed.

There are 5 FSMO roles:
#### Schema Master
- Manages the read/write copy of the AD schema
#### Domain Naming Master (*One for each forest*)
- Manages domain names and ensures that two domains of the same name are not created in the same forest
#### Relative ID (RID) Master (*One per domain*)
- Assigns blocks of RIDs to other DCs within the domain that can be used for new objects.
- Ensures that multiple objects aren't assigned the same SID.
- The domain object SIDs are the domain SID combined with the RID number for the object.
#### Primary Domain Controller (PDC) Emulator (*One per domain*)
#### Infrastructure Master (*One per domain*)

### Global Catalog
A [global catalog (GC)](https://docs.microsoft.com/en-us/windows/win32/ad/global-catalog) is a domain controller that stores copies of ALL objects in an AD forest. It stores full copies of any object within its domain, and partial copies of objects in any other domains in the forest. A normal domain controller only stores info about its own objects, meaning that a GC can be used to query info about any object within any domain in the forest.

### Read-Only Domain Controller (RODC)
Essentially a read-only AD database. An [Read-Only Domain Controller (RODC)](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema) has no AD account passwords in its cache other than its own credentials. They can also be used to:
- have a read-only DNS server
- allow administrator role separation
- reduce replication traffic
- prevent SYSVOL modifications from being replicated to other DCs

### Replication
[Replication](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts) happens when AD objects are updated and transferred from one DC to another. Connection objects are created, *by the Knowledge Consistency Checker (KCC) running on every DC*, whenever a new DC is added to facilitate replication. This syncs changes to all DCs in a forest for DR.

### Service Principal Name (SPN)
A [Service Principal Name (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) uniquely identifies a service instance. They are used by Kerberos authentication to associate an instance of a service with a logon account.

### Group Policy Object (GPO)
[Group Policy Objects (GPOs)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects) are virtual collections of policy settings. Each GPO has a GUID and can contain local file system or AD settings. They can be applied to users and/or computer objects. They can be applied globally in a domain or granularly at the OU level.

### Access Control List (ACL)
An [Access Control List (ACL)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) is an ordered collection of Access Control Entries (ACEs) that apply to an object.

### Access Control Entries (ACEs)
Each [Access Control Entry (ACE)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-entries) in an ACL identifies a trustee (user acc, group acc, or logon session) and lists their rights (allowed, denied, or audited).

### Discretional ACL (DACL)
DACLs define which security principals are granted or denied access to an object; it contains a list of ACEs. When a process tries to access a securable object, the system authorises based on the DACL.

### System ACL (SACL)
Allows admins to log access attempts that are made to secured objects. ACEs specify the types of access attempts that cause the system to generate a record in the security event log.

### Fully Qualified Domain Name (FQDN)
An FQDN is the complete name of a computer or host. `<hostname>.<domain>.<tld>` used to specify an object's location in the DNS tree. Used to locate a host in AD without knowing the IP.

### Tombstone
A [tombstone](https://ldapwiki.com/wiki/Wiki.jsp?page=Tombstone) is a container object in AD that holds deleted AD objects. When an object is deleted from AD, the object remains for a set period of time known as the *Tombstone Lifetime*, and *isDeleted* is set to `True`. Once the lifetime is exceeded, the object is entirely removed. Defaults to 60 or 180 days depending on DC OS version. When an object is deleted in an AD environment without an AD Recycle Bin, it will become a tombstone object. Majority of its attributes will be stripped and it will be places in the *Deleted Objects* container for its lifespan. It can be recovered by any stripped attributes can't.

### AD Recycle Bin
If an object is deleted it goes to this bin for a set period (default 60 days). It is much easier to fully restore the object than from a tombstone.

### SYSVOL
The [SYSVOL](https://social.technet.microsoft.com/wiki/contents/articles/8548.active-directory-sysvol-and-netlogon.aspx) folder, or share, stores copied of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, and often contains other types of scripts used in the AD environment. The contents of this folder is replicated to all DCs using File Replication Services (FRS).

### AdminSDHolder
The [AdminSDHolder](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) object is used to manage ACLs for members of built-in groups in AD marked as privileged. Its a container for the Security Descriptor applied to members of protected groups. The `SDProp` process runs on a schedule on the PDC Emulator DC. By default it runs every hour, checking that members of protected groups have the correct ACLs applied to them. Eg. if an attacker creates a malicious ACL entry for a user in the Domain Admins group, unless they modify other AD settings, the SDProp would remove the new rights.

### dsHeuristics
The [dsHeuristics](https://docs.microsoft.com/en-us/windows/win32/adschema/a-dsheuristics) attribute is a string value on the Directory Service object to define multiple forest-wide configuration settings. This can be used to exclude built-in groups from the [Protected Groups](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) list. This means they won't be modified by the *AdminSDHolder* object.

### adminCount
The [adminCount](https://docs.microsoft.com/en-us/windows/win32/adschema/a-admincount) attribute determines whether or not the SDProp process protects a user. `0` means unprotected. Searching for users with this attribute set to `1` means these are likely privileged accounts that could be of special interest.

### Active Directory Users and Computers (ADUC)
ADUC is a GUI console for managing users, groups, computers and contacts in AD. Can also be used through PowerShell.

### ADSI Edit
A GUI tool used to manage objects in AD. It is more powerful and has more access than ADUC has. You can create, modify or delete any object in an AD. It can however, allow changes that could have devastating effects in an AD.

### sIDHistory
[This](https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-sid-history-attribute) attribute holds any SIDs that na object was assigned previously. It is often used when migrating a user across domains to maintain their access. It can be potentially abused to gain elevated access in another domain if SID Filtering isn't enabled.

## NTDS
![[Windows#NTDS]]

## MSBROWSE
MSBROWSE is a Microsoft networking protocol that was used in early Windows-based LANs to provide browsing services. In older windows versions, we could use `nbtstat -A ip-address` to search for the Master browser. If we see `MSBROWSE` then thats the master browser. We could use `mltest` to query the Windows Master Browser for names of Domain Controllers.
> Largely it is obsolete and replace by SMB and CIFS.