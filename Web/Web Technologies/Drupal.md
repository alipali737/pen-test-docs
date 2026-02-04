```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
An open-source PHP and MySQL/PostgreSQL CMS platform. It can also work with SQLite if no DBMS is installed. Like other CMS' it has thousands of additional modules and themes a user can install from third parties.

## Discovery/Fingerprinting
- `Powered by Drupal message`
- `CHANGELOG.txt` or `README.txt` files (*this has version info normally*)
- Meta tags in the source
- `robots.txt` files that refer to places like `/node`
- `/node/[node-id]` (eg. `1`)

## Tools
### Droopescan
[droopescan](https://github.com/droope/droopescan) is a scanner that can help scan drupal apps:
```bash
droopescan scan drupal --url [target]
```
