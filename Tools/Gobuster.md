```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Gobuster is a web enumeration tool that supports a number of features (dir, dns, forced browsing etc). Written in Go, it is much faster than many of the previous generation tools for this purpose.

## Installation
```
Download from https://github.com/OJ/gobuster/releases
---
docker pull ghcr.io/oj/gobuster:latest
---
go install github.com/OJ/gobuster/v3@latest
---
or build from github source
```

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/OJ/gobuster
## Usage
### Directory/File Enumeration
```
gobuster dir -u [target URL] -w [wordlist]
```
This lets us discover pages of a website that we might be able to gain access to.

### DNS Subdomain Enumeration
```
1. Add a DNS to /etc/resolv.conf

2. Run gobuster
gobuster dns -d [domain] -w [wordlist]

// Found: blog.example.com
// Found: portal.example.com
```