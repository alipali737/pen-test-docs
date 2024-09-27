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
## How it works


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
- *system schema* (*sys*): [docs](https://dev.mysql.com/doc/refman/8.0/en/system-schema.html)
	- `host_summary` table contains host information : `select host, unique_users from host_summary;`
- *information schema* (*information_schema*): metadata database

## Potential Capabilities
- Potentially gain access to sensitive information in the database
- View sensitive logs and error outputs that could indicate further attack possibilities

## Enumeration Checklist

| Goal                          | Command(s)                                                                                                                                                                                  | Refs |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- |
| Identify the service via Nmap | sudo nmap [ip] -sC -sV -p3306 --script mysql*                                                                                                                                               |      |
| Connect with a client         | mysql -u [user] -p[password] -h [ip]                                                                                                                                                        |      |
| Show information              | show databases;<br><br>use [database name];<br><br>show tables;<br><br>show columns from [table];<br><br>select \* from [table];<br><br>select \* from [table] where [column] = "[string]"; |      |
| Get version                   | select version();                                                                                                                                                                           |      |
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