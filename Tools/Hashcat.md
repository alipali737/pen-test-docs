```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
A password & hash cracking tool, similar to [[John The Ripper]]. It specifically takes advantage of GPU processing which can have drastically faster speeds. 

Hashcat can also create custom password lists based on a set of rules given.

## Installation
- Download the binary from the hashcat website
## Documentation
**Cheatsheet:** 
**Website:** https://hashcat.net/hashcat/
**HTB Module:** [Cracking Passwords with Hashcat](https://academy.hackthebox.com/course/preview/cracking-passwords-with-hashcat)
## Usage
### Password mutation
A rule file can be created with patterns that will be used to mutate each password in the `password_list` provided in a run. The syntax for the rules can be found in the [documentation](https://hashcat.net/wiki/doku.php?id=rule_based_attack). Each rule must be on a separate line in a file:
```sh
$ cat custom.rules

:
l
u
c
c sa@ so0
$!
$! c
```

| **Function** | **Description**                                   |
| ------------ | ------------------------------------------------- |
| `:`          | Do nothing.                                       |
| `l`          | Lowercase all letters.                            |
| `u`          | Uppercase all letters.                            |
| `c`          | Capitalize the first letter and lowercase others. |
| `sXY`        | Replace all instances of X with Y.                |
| `$!`         | Add the exclamation character at the end.         |
To then generate the list, you would use:
```sh
# `sort -u` sorts the password list lexographically and removes duplicates
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```
> There are built in rules in hashcat, a popular one is `best64.rule`.