```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Nikto* is a powerful open-source web server scanner. Its primary function is as a vulnerability scanner but it also includes fingerprinting capabilities that can be used to identify a website's technology stack.

## Installation
```
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl
```

## Documentation
**Cheatsheet:** 
**Website:** 
## Usage
```
nikto -h [target]
```

```
nikto -h [target] -Tuning b
```
> *-Tuning b* specifies only to run the software identification modules. (Useful for fingerprinting only)