---
layout: page
title: Basic SQL Syntax
nav_order: -1
---
# Basic SQL Syntax
SQL syntax can differ between RDBMS but they all follow the [ISO Standard](https://en.wikipedia.org/wiki/ISO/IEC_9075).

SQL can be used to perform the following actions:
- Retrieve data
- Update data
- Delete data
- Create new tables and databases
- Add / remove users
- Assign permissions to these users

## MySQL
#### Authentication
```shell
mqsql -u root -p
```
***Note:** we do not pass the `-p` with the password as the password could be stored in plain text in the bash_history file. Instead it will prompt us to securely enter the password.*
***Tip:** if a password is passed, there should be no space eg. `-p<password>`*

By default the `localhost` address will be used if not passed, otherwise a host & port can be passed using `-h <host> -P <port>`

The default port for MySQL/MariaDB is (`3306`)

#### Creating the DB
Once authentiacted you can create a database with:
```mysql
CREATE DATABASE users;

> Query OK, 1 row affected (0.02 sec)
```

SQL expects all queries to end with a `;`

#### Listing all DB's
```mysql
SHOW DATABASES;
```

You will get a list of all the available databases
```shell
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
```

#### Selecting a DB
```mysql
USE users;

> Database changed
```

SQL commands aren't case sensitive but the passed fields are

### Tables
Databases store data in the form of tables, containing rows and columns with the intersections being cells. Created with a fixed set of columns.

Column datatypes define what value can be stored. Common types are `numbers`, `strings`, `date`, `time`, and `binary data`. Other datatypes can be specific to the DBMS. MySQL's full list of types can be found [here](https://dev.mysql.com/doc/refman/8.0/en/data-types.html)

#### Creating a table
```mysql
CREATE TABLE logins (
	id INT,
	username VARCHAR(100),
	password VARCHAR(100),
	date_of_joining DATETIME
);
```

#### Listing all tables
```mysql
SHOW TABLES;
```
```
+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
```

DESCRIBE can also be used to get information on a table
```mysql
DESCRIBE logins;
```
```
+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
```

#### Table Properties
There are lots of [properties](https://dev.mysql.com/doc/refman/8.0/en/create-table.html) that can be used when creating a table.

eg. we can have the `id` field `AUTO_INCREMENT`
```mysql
id INT NOT NULL AUTO_INCREMENT,
```

`NOT NULL` makes a field required (therefore never empty)
`UNIQUE` also makes sure that its always a unique value being entered
```mysql
username VARCHAR(100) UNIQUE NOT NULL,
```

`NOW()` gets the current datetime
`DEFAULT` specifies the default value
```mysql
date_of_joining DATETIME DEFAULT NOW(),
```

Finally we need to set a `PRIMARY KEY` for our table
```mysql
PRIMARY KEY (id)
```

Our final create table would then look like:
```mysql
CREATE TABLE logins (
	id INT NOT NULL AUTO_INCREMENT,
	username VARCHAR(100) UNIQUE NOT NULL,
	password VARCHAR(100) NOT NULL,
	date_of_joining DATETIME DEFAULT NOW(),
	PRIMARY KEY (id)
);
```
