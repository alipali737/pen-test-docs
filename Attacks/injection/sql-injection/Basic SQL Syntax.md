---
layout: page
title: Basic SQL Syntax
parent: SQL Injection
grand_parent: Injection
---

# {{ page.title }}
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

SQL syntax can differ between RDBMS but they all follow the [ISO Standard](https://en.wikipedia.org/wiki/ISO/IEC_9075).

SQL can be used to perform the following actions:
- Retrieve data
- Update data
- Delete data
- Create new tables and databases
- Add / remove users
- Assign permissions to these users

## Database Interaction
#### Authentication
{% highlight shell %}
mqsql -u root -p
{% endhighlight %}
***Note:** we do not pass the `-p` with the password as the password could be stored in plain text in the bash_history file. Instead it will prompt us to securely enter the password.*
***Tip:** if a password is passed, there should be no space eg. `-p<password>`*

By default the `localhost` address will be used if not passed, otherwise a host & port can be passed using `-h <host> -P <port>`

The default port for MySQL/MariaDB is (`3306`)

#### Creating the DB
Once authentiacted you can create a database with:
{% highlight sql %}
CREATE DATABASE users;

> Query OK, 1 row affected (0.02 sec)
{% endhighlight %}

SQL expects all queries to end with a `;`

#### Listing all DB's
{% highlight sql %}
SHOW DATABASES;
{% endhighlight %}
You will get a list of all the available databases
{% highlight shell %}
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
{% endhighlight %}

#### Selecting a DB
{% highlight sql %}
USE users;

> Database changed
{% endhighlight %}

SQL commands aren't case sensitive but the passed fields are

### Tables
Databases store data in the form of tables, containing rows and columns with the intersections being cells. Created with a fixed set of columns.

Column datatypes define what value can be stored. Common types are `numbers`, `strings`, `date`, `time`, and `binary data`. Other datatypes can be specific to the DBMS. MySQL's full list of types can be found [here](https://dev.mysql.com/doc/refman/8.0/en/data-types.html)

#### Creating a table
{% highlight sql %}
CREATE TABLE logins (
	id INT,
	username VARCHAR(100),
	password VARCHAR(100),
	date_of_joining DATETIME
);
{% endhighlight %}

#### Listing all tables
{% highlight sql %}
SHOW TABLES;
+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
{% endhighlight %}

DESCRIBE can also be used to get information on a table
{% highlight sql %}
DESCRIBE logins;
+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
{% endhighlight %}

#### Table Properties
There are lots of [properties](https://dev.mysql.com/doc/refman/8.0/en/create-table.html) that can be used when creating a table.

eg. we can have the `id` field `AUTO_INCREMENT`
{% highlight sql %}
id INT NOT NULL AUTO_INCREMENT,
{% endhighlight %}

`NOT NULL` makes a field required (therefore never empty)
`UNIQUE` also makes sure that its always a unique value being entered
{% highlight sql %}
username VARCHAR(100) UNIQUE NOT NULL,
{% endhighlight %}

`NOW()` gets the current datetime
`DEFAULT` specifies the default value
{% highlight sql %}
date_of_joining DATETIME DEFAULT NOW(),
{% endhighlight %}

Finally we need to set a `PRIMARY KEY` for our table
{% highlight sql %}
PRIMARY KEY (id)
{% endhighlight %}

Our final create table would then look like:
{% highlight sql %}
CREATE TABLE logins (
	id INT NOT NULL AUTO_INCREMENT,
	username VARCHAR(100) UNIQUE NOT NULL,
	password VARCHAR(100) NOT NULL,
	date_of_joining DATETIME DEFAULT NOW(),
	PRIMARY KEY (id)
);
{% endhighlight %}

## SQL
- Case insensitive keyword-based language
- Statements can be separated with a `;`
- [Cheat Sheet](https://www.codecademy.com/learn/learn-sql/modules/learn-sql-manipulation/cheatsheet)

### Syntax
#### Manipulation
- **CREATE DATABASE** - creates a new database
- **ALTER DATABASE** - modifies a database
- **CREATE TABLE** - creates a new table
- **ALTER TABLE** - modifies a table
- **DROP TABLE** - deletes a table
- **CREATE INDEX** - creates an index (search key)
- **DROP INDEX** - deletes an index
- **UPDATE** - updates data in a database (`UPDATE {table} SET {column_1} = {value_1}, ... ;`)
- **INSERT INTO** - inserts new data into a database (`INSERT INTO {table} ({column_1}, ... ) VALUES ({value_1, ... };)`)
- **DELETE** - deletes data from a database
##### Column Constaints
- **PRIMARY KEY** - constraint can be used to uniquely identify the row
- **UNIQUE** - columns have a different value for every row.
- **NOT NULL** - columns must have a value.
- **DEFAULT** - assigns a default value for the column when no value is specified.

#### Queries
- **SELECT** - Extracts data from a database
- **FROM** - Name(s) of table(s) to retrieve from
- **WHERE** - Filter the results
	- Operators:
		- `=` - Equals
		- `>` - Greater than
		- `<` - Less than
		- `>=` - Greater or equal
		- `<=` - Less or equal
		- `<>` - Not equal
		- `BETWEEN` - Range
		- `LIKE` - Pattern
			- `%` - wildcard that matches zero or more unspecified characters
			- `_` - wildcard that matches a single unspecified character
		- `IN` - Multiple possible values 
		- `IS NULL` - Tests for if Null (can be `IS NOT NULL`)
- **ORDER BY** - Sort the results (Sorts by ascending by default, `DESC` can be specified to reverse `ORDER BY ... ASC|DESC`)
- **GROUP BY** - Group results by identical values
- **DISTINCT** - Selects only distinct (unique) values `SELECT DISTINCT ... FROM ... ;`
- **LIMIT** - limit the number of rows in a result set
- **AND**
- **OR**
- **NOT**
- **AS** - rename a column in the result set
#### Aggregate Functions
- **COUNT()** - Counts a column's number of records
- **SUM()** - returns the sum of all a column's values
- **MAX()** - returns the max value of a column
- **MIN()** - returns the min value of a column
- **AVG()** - returns the average value of a column
- **HAVING** - extension of `GROUP BY` to further filter the results, often used to filter by an aggregate function
- **ROUND()** - round a value to a specific number of places

#### Multiple Tables
- **LEFT JOIN** - joins two tables in a result set based on a condition
- **WITH** - stores the result in a temporary table
- **UNION** - combines results from multiple `SELECT` statements
- **CROSS JOIN** - combines rows from each row in one table with each row in another table in the result set
- **JOIN** - combine results from multiple tables based on a common column
