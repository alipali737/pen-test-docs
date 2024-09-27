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

Often used with (Linux, Apache, MySQL, PHP - *LAMP*) or Nginx (*LEMP*).

**Standard Port:** 

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
- `user` : Which user to run the service as (stored plaintext)
- `password` : Password for the DB user
- `admin_address` : IP address for the admin network interface
- `debug` : Current debug settings (eg. logging)
- `sql_warnings` : Whether a single-row INSERT statement should produce warnings
- `secure_file_priv` : Limit the effect of data import and export operations

## Potential Capabilities
- 

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
### Nmap Scripts
- 