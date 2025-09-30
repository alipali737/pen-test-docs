```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[ffuf](https://github.com/ffuf/ffuf) is a go-based web fuzzing tool that can cover:
- Directory enumeration
- File and extension discovery
- Identifying vhosts & subdomains
- Parameter discovery
- Parameter value enumeration

## Installation
```
# Via homebrew (MacOS)
brew install ffuf

# Prebuild releases
https://github.com/ffuf/ffuf/releases/latest

# Go package
go install github.com/ffuf/ffuf/v2@latest

# Go build
git clone https://github.com/ffuf/ffuf ; cd ffuc ; go get ; go build
```

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/ffuf/ffuf
## Usage

### Directory Fuzzing
```bash
ffuf -w [wordlist]:[KEYWORD] -u [url]/[KEYWORD]
ffuf -w directory-wordlist.txt:FUZZ -u https://example.com/FUZZ
```

### Extension Fuzzing
```bash
ffuf -w [wordlist]:[KEYWORD] -u [url]/[page].[KEYWORD]
ffuf -w extension-wordlist.txt:FUZZ -u https://example.com/index.FUZZ
```
> Check whether the wordlist already has the `.` or not as a prefix

### Page Fuzzing
```bash
ffuf -w directory-wordlist.txt:FUZZ -u https://example.com/FUZZ.php
```

### Recursive Fuzzing
```bash
ffuf -w directory-wordlist.txt:FUZZ -u https://example.com/FUZZ -recursion -recursion-depth 1 -e .php -v
```
> `-recursion-depth` is how many subdirectories we want to scan (this can drastically affect scan time), 1 is just a single sub-level
> `-e` is the extension we want to apply
> `-v` gives us the full URLs so its easier to see the results