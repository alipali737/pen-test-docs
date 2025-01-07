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
- 1434/udp
- 2433/tcp - MSSQL in 'hidden' mode

## How it works
### Authentication Mechanisms
- *Windows authentication mode* : integrates with Windows/Active Directory for its users and groups who are trusted to log in to SQL server. Integrates with the SSO so users don't need to present additional credentials.
- *Mixed mode* : Supports Windows/AD accounts as well as holding its own SQL Server accounts. Usernames and passwords pairs are stored on the SQL server.

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
- System command execution

### RCE
The extended stored procedures (`xp_cmdshell`) allows us to execute system commands via SQL. It is *disabled by default* but can be enabled using the [Policy-Based Management](https://docs.microsoft.com/en-us/sql/relational-databases/security/surface-area-configuration) or by executing [sp_configure](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option). The windows process spawned by `xp_cmdshell` has the same privileges as the SQL Server service account. `xp_cmdshell` operates synchronously.
```sql
1> xp_cmdshell 'whoami'
2> GO

output
-------------
no service\mssql$sqlexpress
NULL
(2 rows affected)
```

If it is disabled, we can change it via `sp_configure`:
```sql
-- To allow advanced options to be changed
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options
RECONFIGURE
GO

-- To enable the feature
EXECUTE sp_configure 'xp_cmdshell', 1
GO

-- To update the currently configured value for the featuer
RECONFIGURE
GO
```

> There are other methods to get command execution, such as adding [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/adding-an-extended-stored-procedure-to-sql-server), [CLR Assemblies](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/introduction-to-sql-server-clr-integration), [SQL Server Agent Jobs](https://docs.microsoft.com/en-us/sql/ssms/agent/schedule-a-job?view=sql-server-ver15), and [external scripts](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-execute-external-script-transact-sql). However, besides those methods there are also additional functionalities that can be used like the `xp_regwrite` command that is used to elevate privileges by creating new entries in the Windows registry.
## Enumeration Checklist

| Goal                               | Command(s)                                                                                                                                                                                                                                                                                          | Refs                                                                                                                  |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Nmap script scan                   | sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=[PORT],mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p [PORT] [IP] |                                                                                                                       |
| Metasploit scanner for information | scanner/mssql/mssql_ping                                                                                                                                                                                                                                                                            |                                                                                                                       |
| mssqlclient                        | python mssqlclient.py [user]:[pass]@[ip] -windows-auth                                                                                                                                                                                                                                              | [cheatsheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)                     |
| CLIs                               | $ sqsh -S [IP] -U [user] -P [pass]<br><br>C:\\> sqlcmd -S [IP] -U [user] -P [pass]                                                                                                                                                                                                                  | [sqsh](https://en.wikipedia.org/wiki/Sqsh)<br><br>[sqlcmd](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility) |
> If using Windows authentication you must specify a domain or a hostname otherwise it will assume it is SQL Server Authentication.
> Eg. `<SERVER_NAME>\\<ACCOUNT_NAME>` (for local) or `.\\<ACCOUNT_NAME>` (for domain)
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