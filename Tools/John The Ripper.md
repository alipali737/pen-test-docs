```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
John is a tool for checking the strength of and cracking encrypted (or hashed) passwords. It utilises brute force or dictionary attacks.

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/openwall/john
## Usage
### Single Crack Mode
This is the simplest mode to run, it take a list of hashes to crack and a single wordlist (*or uses it's built-in list*).
```shell
john --format=<hash_type> <hashes_file>
john --format=sha256 hashes_to_crack.txt
```
> We can use `--wordlist` and `--rules` to further configure the tool 

### Wordlist Mode
This mode uses a (*or multiple*) wordlist(*s*) to crack the hashes. It is typically best for multiple hashes to be cracked at the same time. We can also use the built-in `--rules` to generate additional candidates from our wordlist (eg. adding numbers, capitalisations, or special characters).
```sh
john --wordlist=<wordlist(s)> --rules <hash_file>
john --wordlist=rockyou.txt --rules hashes.txt
john --wordlist=list1.txt,list2.txt,list3.txt --rules hashes.txt
```

### Incremental Mode
This takes a character 