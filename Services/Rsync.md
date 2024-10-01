```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
A fast and efficient tool for locally and remotely copying files. Uses a delta-transfer algorithm to reduce the amount of data transmitted if a version of the file already exists (sends only the differences).

Useful for backups or mirroring. Looks at file size & last modified time to identify which files should be copied.

**Standard Port:** 
- 873/tcp

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works


## Configuration
- Can be configured to use SSH

## Potential Capabilities
- [Hack Tricks](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync)

## Enumeration Checklist

| Goal                     | Command(s)                                                                                                                                          | Refs                                                                                                         |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Banner grabbing          | nc -vn [ip] 873<br><br>                                                                                                                             | https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync#banner-and-manual-communication |
| Enumerate shared folders | sudo nmap [ip] -sV --script "rsync-list-modules" -p873<br><br>auxiliary/scanner/rsync/modules_list<br><br>rsync -av --list-only rsync://[ip]:[port] |                                                                                                              |
### Nmap Scripts
- 