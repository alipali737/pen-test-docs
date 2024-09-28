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
- Each database instance in Oracle RDBMS has a *System Identifier* (*SID*). When a client connects they need to specify the SID they want to connect to. Tools like [[Nmap]], [[Hydra]], *odat.py* can be used to enumerate or guess SIDs.
> ODAT can be installed with the following script
```
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```
## Configuration
- Configured via `tnsnames.ora` (client-side config) and `listener.ora` (Server-side config) typically located in the `$ORACLE_HOME/network/admin`
- Oracle Databases can be protected using a *PL/SQL* Exclusion List (`PlsqlExclusionsList`). It is a user created file in the `$ORACLE_HOME/sqldeveloper` directory, that contains PL/SQL packages or types that should be excluded from execution. It serves as a blacklist.

## Potential Capabilities
- 

## Enumeration Checklist

| Goal                                    | Command(s)                                                                                          | Refs                                                                                                                                                                                                                                                                                                                                |
| --------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Oracle Database Attacking Tool (*ODAT*) | odat.py all -s [IP]                                                                                 |                                                                                                                                                                                                                                                                                                                                     |
| Guess DB SIDs                           | sudo nmap -p1521 --script=oracle-sid-brute                                                          |                                                                                                                                                                                                                                                                                                                                     |
| Connect to an Oracle DB                 | sqlplus [user]/[pass]@[ip/[SID]<br><br>sqlplus [user]/[pass]@[ip]/[SID] as sysdba                   | [error while loading shared libraries: libsqlplus.so](https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared#:~:text=sudo%20sh%20%2Dc%20%22echo%20/usr/lib/oracle/12.2/client64/lib%20%3E%20/etc/ld.so.conf.d/oracle%2Dinstantclient.conf%22%3Bsudo%20ldconfig) |
| Database interactions                   | select table_name from all_tables;<br><br>select * from user_role_privs;                            |                                                                                                                                                                                                                                                                                                                                     |
| Password hashes                         | select name, password from sys.user$;                                                               |                                                                                                                                                                                                                                                                                                                                     |
| Upload a file (possibly a web shell)    | odat.py utlfile -s [ip] -d [SID] -U [user] -P [pass] --sysdba --putFile [put location] [local file] |                                                                                                                                                                                                                                                                                                                                     |
|                                         |                                                                                                     |                                                                                                                                                                                                                                                                                                                                     |
### Nmap Scripts
- oracle-sid-brute