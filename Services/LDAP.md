```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[Lightweight Directory Access Protocol (LDAP)](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) is an open-source and cross-platform protocol for authentication in directory services (such as [[Active Directory]]).

You may also come across LDAP servers that aren't affiliated with a directory service like [[Active Directory]], these often are deployed with [OpenLDAP](https://en.wikipedia.org/wiki/OpenLDAP).

**Standard Port:** 
- 389/tcp - for LDAP
- 636/tcp - for LDAPS (LDAP over SSL)


## How it works
1. A session is created by connecting to an LDAP server (AKA a *Directory System Agent*).
2. The Domain Controller listens for LDAP requests from the LDAP server.
3. The DC then performs its authentication using the LDAP protocol and responds
4. The LDAP server then responds to the user with their information

> An AD server uses the LDAP protocol in the same way an Apache webserver uses the HTTP protocol. 
> When using AD, LDAP is setup to authenticate credentials against a `BIND` operation to set the authentication state of the LDAP session

LDAP has two types of authentication:
- *Simple Authentication*: This includes anonymous, unauthenticated, and username/password authentication. Simple auth means that a *username* and *password* create a `BIND` request to authenticate to the LDAP server.
- *SASL Authentication*: [The Simple Authentication and Security Layer (SASL)](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer) framework uses other authentication services (eg. [[Kerberos]]), to bind to the LDAP server and then uses this auth service to authenticate to LDAP.
## Configuration


## Potential Capabilities
- 

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
### Nmap Scripts
- 