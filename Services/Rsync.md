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
- Find the config file with : `find /etc \( -name rsyncd.conf -o -name rsyncd.secrets \)`

## Potential Capabilities
- [Hack Tricks](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync)

## Enumeration Checklist

| Goal                     | Command(s)                                                                                                                                          | Refs                                                                                                         |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Banner grabbing          | ```<br>nc -vn [ip] 873<br>#list<br>```<br>                                                                                                          | https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync#banner-and-manual-communication |
| Enumerate shared folders | sudo nmap [ip] -sV --script "rsync-list-modules" -p873<br><br>auxiliary/scanner/rsync/modules_list<br><br>rsync -av --list-only rsync://[ip]:[port] |                                                                                                              |
| List a shared folder     | rsync -av --list-only rsync://[ip]:[port]/[share-name]                                                                                              |                                                                                                              |
| Copy files from a share  | rsync -av rsync://[ip]:[port]/[share-name] ./rsync-shared<br><br>rsync -e "ssh -p2222" -av rsync://[ip]:[port]/[share-name] ./rsync-shared          | [rsync over ssh guide](https://phoenixnap.com/kb/how-to-rsync-over-ssh)                                      |
| Upload files             | rsync -av [local file] rsync://[ip]:[port]/[location]                                                                                               |                                                                                                              |
> To authenticate with `rsync` you can use `rsync://[username]@[ip]:[port]/...` and this will prompt for the password.
### Nmap Scripts
- 