```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Oracle Transparent Network Substrate* (*TNS*) server is a protocol for communication between Oracle databases and applications over networks. It has a built in encryption mechanism. It supports *IPX/SPX* and *TCP/IP*. It has been updated to support *IPv6* and *SSL/TLS*. 

Often used with other Oracle services such as : *Oracle DBSNMP*, *Oracle Databases*, *Oracle Application Server*, *Oracle Enterprise Manager*, *Oracle Fusion Middleware*, and web servers.

Some older version of TNS have default passwords set.

**Standard Port:** 
- Listener : 1521/tcp (configurable)

**Version Names:** 

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
- The listener supports various network protocols, including: *TCP/IP*, *UDP*, *IPX/SPX*, and *AppleTalk*.
- By default, only authorised hosts can connect using some basic authentication (IPs, usernames, passwords, hostnames).
- The server will use Oracle Net Services to encrypt the communication between the client and server.
## Configuration
- Configured via `tnsnames.ora` (client-side config) and `listener.ora` (Server-side config) typically located in the `$ORACLE_HOME/network/admin`
- Oracle Databases can be protected using a *PL/SQL* Exclusion List (`PlsqlExclusionsList`). It is a user created file in the `$ORACLE_HOME/sqldeveloper` directory, that contains PL/SQL packages or types that should be excluded from execution. It serves as a blacklist.

## Potential Capabilities
- 

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
### Nmap Scripts
- 