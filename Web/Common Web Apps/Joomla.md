```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
[Joomla](https://www.joomla.org/) is another open-source CMS using PHP & MySQL. It can be enhanced with templates and extensions too.

It can be discovered through the meta tags or in the robots.txt file. Sometimes the README will also be left over.

## Tools
### Droopescan
[droopescan](https://github.com/droope/droopescan) is a scanner that can help scan joomla apps:
```bash
droopescan scan joomla --url [target]
```

### JoomlaScan
[JoomlaScan](https://github.com/drego85/JoomlaScan) also does a similar job but requires python 2.7

### joomla-brute.py
[joomla-brute.py](https://github.com/ajnik/joomla-bruteforce) is a login brute forcer python script for joomla.

```bash
sudo python3 joomla-brute.py -u [target] -w [wordlist] -usr [user]
```