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
```bash
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges
```
**Website:** https://github.com/ffuf/ffuf
**Useful Wordlists:**
- `seclists/Discovery/DNS/subdomains-top1million-5000.txt` : sub-domain & vhost fuzzing
- `seclists/Discovery/Web-Content/directory-list-2.3-small.txt` : directory & page fuzzing
- `seclists/Discovery/Web-Content/web-extensions.txt` : extension fuzzing
- `seclists/Discovery/Web-Content/burp-parameter-names.txt` : param discovery
## Usage
#### Adding a host to /etc/hosts
```bash
sudo sh -c 'echo "[ip]  [host]" >> /etc/hosts'
```

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

### Sub-domain Fuzzing
```bash
ffuf -w subdomains.txt:FUZZ -u https://FUZZ.example.com/
```
> This won't work for domains in the /etc/hosts file as it won't resolve

### VHost Fuzzing
A vhost is basically a sub-domain but served on the same server as other hosts, meaning it has the same IP. They may or may not have public DNS records.
```bash
ffuf -w sub-domains.txt:FUZZ -u https://example.com/ -H 'Host: FUZZ.example.com'
```
> We are expecting to see consistent status codes but its the size changing that reveals if we actually hit something, we can filter size with `-fs [size]`

### Parameter Fuzzing - GET
```bash
ffuf -w params.txt:FUZZ -u https://example.com/admin.php?FUZZ=blah
```

### Parameter Fuzzing - POST
Data in a post request needs to be in the data section, not the URL.
```bash
ffuf -w params.txt:FUZZ -u https://example.com/admin.php -X POST -d 'FUZZ=key'
```
> For some languages, they only accept certain `Content-Type`
> Eg. For `PHP` you need to add `-H 'Content-Type: application/x-www-form-urlencoded'`

### Parameter Value Fuzzing
Often, we will need custom-wordlists when fuzzing parameter values. Sometimes we can find pre-made lists (eg. usernames, passwords etc). Other times we will need to create our own. 
Eg. To create a sequential ID list
```bash
for i in $(seq 1 1000); do echo $1 >> ids.txt; done
```