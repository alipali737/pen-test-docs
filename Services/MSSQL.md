```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Microsoft SQL* is a closed-source DBMS initially written for windows (it can run on Linux and MacOS now though). It has strong native support for `.NET`.

*SQL Server Management Studio* (*SSMS*) can be included in the installation of MSSQL. It is a standalone client application that allows for remote configuration of MSSQL.

**Standard Port:** 
- 1433/tcp - default MSSQL server port

**Version Names:** 

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works


## Configuration
### Default Databases
- *master* : system information for an SQL server
- *model* : template database for all new databases created
- *msdb* : SQL server agent uses this database to schedule jobs & alerts
- *tempdb* : stores temporary objects
- *resource* : read-only database containing system objects included with SQL server

Unless configured, the MSSQL service will typically run as `NT SERVICE\MSSQLSERVER`. Connections can be done through Windows Authentication and by default encryption isn't enforced.

## Potential Capabilities
- MSSQL clients might not be using an encrypted connection to the MSSQL server
- Self-signed certificates might allow you to spoof them and make a connection
- Weak or default `sa` credentials. Sometimes it may be forgotten to delete this account.

## Enumeration Checklist

| Goal                               | Command(s)                                                                                                                                                                                                                                                                                          | Refs                                                                                              |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Nmap script scan                   | sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=[PORT],mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p [PORT] [IP] |                                                                                                   |
| Metasploit scanner for information | scanner/mssql/mssql_ping                                                                                                                                                                                                                                                                            |                                                                                                   |
| mssqlclient                        | python mssqlclient.py [user]:[pass]@[ip] -windows-auth                                                                                                                                                                                                                                              | [cheatsheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet) |
### Nmap Scripts
- ms-sql-info
- ms-sql-empty-password
- ms-sql-xp-cmdshell
- ms-sql-config
- ms-sql-ntlm-info
- ms-sql-tables
- ms-sql-hasdbaccess
- ms-sql-dac
- ms-sql-dump-hashes