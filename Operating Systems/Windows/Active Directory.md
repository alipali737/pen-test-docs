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
### Forests
Forests are the top level element of the AD structure, forests can:
- Contain multiple domains
- Include child/subdomains

## NTDS
![[Windows#NTDS]]