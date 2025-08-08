```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Bloodhound has several collectors (*A collector gathers the information in the AD environment*) which produce JSON files that can be uploaded to the Bloodhound GUI tool.

The GUI is an application that can visually map out permission relationships within an [[Active Directory]] environment. It can be used to identify privilege relationships that can be exploited. We can also use the [Cypher language](https://blog.cptjesus.com/posts/introtocypher) to create (or use pre-defined) queries to aid our investigations.

There are two main collectors:
- [SharpHound collector](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) : for running on a Windows host
- [BloodHound.py](https://github.com/fox-it/BloodHound.py) : for running on a Linux host (*a.k.a `bloodhound-python`*)

## Installation
### BloodHound.py
`pip install bloodhound-ce`
The BloodHound.py CE ingestor will add a command line tool `bloodhound-ce-python` to your PATH.
### Sharphound
https://github.com/SpecterOps/BloodHound-Legacy/tree/master/Collectors
### BloodHound GUI
https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart

## Documentation
**Cheatsheet:** [custom Cypher queries](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
**Website:** https://github.com/SpecterOps/BloodHound
## Usage
### Collecting from Linux
```bash
sudo bloodhound-ce-python -u '[user]' -p '[pass]' -ns [dc-ip] -d [domain] -c all
```
> `-c` is the collection method, `all` gives us the most data

### Start bloodhound GUI
```bash
bloodhound-cli
```
