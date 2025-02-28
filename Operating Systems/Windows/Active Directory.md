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
#### Domain Naming Master (*One for each forest*)
#### Relative ID (RID) Master (*One per domain*)
#### Primary Domain Controller (PDC) Emulator (*One per domain*)
#### Infrastructure Master (*One per domain*)

### Global Catalog
A [global catalog (GC)](https://docs.microsoft.com/en-us/windows/win32/ad/global-catalog) is a domain controller that stores copies of ALL objects in an AD forest. It stores full copies of any object within its domain, and partial copies of objects in any other domains in the forest. A normal domain controller only stores info about its own objects, meaning that a GC can be used to query info about any object within any domain in the forest.




## NTDS
![[Windows#NTDS]]