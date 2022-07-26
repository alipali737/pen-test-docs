# Introduction
User-supplied information can be used to construct database queries. 

User <--> Tier 1 (Front-end Website) <--> Tier 2 (Application Server) <--> DataBase Management System

An SQL injection refers to an attack on a **Relational database** such as `MySQL` (whereas injections against non-relational databases, such as MongoDB, are NoSQL injections)

### SQL Injection (SQLi)
First thing that needs to be done is inject SWL code outside the expected user input limits, so it's not executed as user input. The most basic case this can be done by inserting (`'` or `"`) to escape the limits of user input.

Next you need to find a way to execute a different SQL query. This can be done by adding an extra query to the end of the generated one using [stacked](https://www.sqlinjection.net/stacked-queries/) queries or  using [Union](https://www.mysqltutorial.org/sql-union-mysql.aspx/) queries.

Finally we then need to interpret it or capture it on the web application's front end.

## Database Management Systems (DBMS)
A DBMS helps create, define, host and manage databases. Various types exist such as file-based, Relational DBMS (RDBMS), NoSQL, Graph based, and Key/Value stores.

DBMS's can be interacted with multiple ways, such as CLI's GUI's or API's.

Key features of a DBMS include:

| Feature | Description |
| --- | --- |
| Concurrency | Be able to handle multiple users interacting with the database simultaneously without corrupting or losing any data |
| Consistency | With multiple users the data base needs to remain consistent and valid |
| Security | Need permission and user authentication controls to prevent unauthorized viewing or editing of data |
| Reliability | Easy to backup and roll back to a previous state in case of data loss or breach |
| Structured Query Language | SQL simplifies user interaction with the database with an intuitive syntax supporting various operations |

**A two-tiered architecture**
![[Pasted image 20220409175513.png]]
**Tier I** usually consists of client-side applications such as websites or GUI programs. High-level interactions that pass data to **Tier II** through API calls or other requests.

**Tier II** is middleware, which interprets these events and puts them in a form required by the DBMS. 

**Application Layer** uses specific libraries and drivers based on the type of DBMS to interact with them. Processes requests from the second tier. Returns any requested data or error codes.

*Note: It is possible to host the application server as well as the DBMS in the same host but databases with large amounts of data supporting many users are typically hosted seperately for performance and scalability*

### Types of Databases
Databases fall into 2 catagories in general, `Relational Databases` and `Non-Relational Databases`. Only Relation databases utilize SQL, while Non-Relation databases utilize a variety of methods for communicating.

#### Relational Databases
A relational database uses a schema, a template, to dictate the data structure stored in the database. Tables in a relational database are associated with keys that provide a quick database summary or access to the specific row or column when needed. These tables, also called entities, are related to each other.

To link multiple tables using a key you need a `relational database management system (RDBMS)`. The relationship between tables within a database is called a schema.

### Non-relational Databases
- Don't use rows, columns, tables or prime keys, relationships or schemas.
- Also called a `NoSQL` database.
- Instead it uses, various storage models, depending on the type of data stored.
- Very scalable and felixable due to their lack of defined structure.

**4 Common storage models for NoSQL:**
- Key-Value
- Document-Based
- Wide-Column
- Graph

Most common example of a NoSQL database is `MongoDB`


