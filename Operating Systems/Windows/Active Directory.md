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
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
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

## NTDS
![[Windows#NTDS]]