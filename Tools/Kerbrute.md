```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Kerbrute is a stealthy domain account enumeration tool. Kerberos pre-authentication failures do no trigger logs or alerts so its really good for a stealthy approach.

The outputs of this tool can then be used for targeted password spraying attacks and further exploitation.
## Installation
```bash
git clone https://github.com/ropnop/kerbrute.git

# Can be windows, linux, or mac (use `make help`)
make linux

ls dist/
```
> Pre-compiled binaries available here: https://github.com/ropnop/kerbrute/releases/latest
## Documentation
**Cheatsheet:** 
**Website:** [Kerbrute](https://github.com/ropnop/kerbrute)
## Usage
### Username Enumeration
```bash
$ kerbrute userenum -d <domain> --dc <domain-controller-ip> <wordlist> -o <output-file>
$ kerbrute userenum -d EXAMPLE.LOCAL --dc 1.2.3.4 usernames.txt -o valid_ad_users
```
> A useful wordlist to use is any of these : [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

