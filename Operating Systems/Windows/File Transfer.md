```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
Sometimes to bypass defences and detection mechanisms, we need to use various methods (sometimes in-conjunction with one another) to transfer files to/from a target system.

## PowerShell Base64 Encode & Decode
- We can encode a payload as Base64, copy and paste it to the other system (eg. via a terminal), and decode it on the system
- Doesn't require any network communication to transfer the file (only shell connection)
- It is important to check the hash of the payload on both sides to ensure its transferred correctly (eg. MD5)

### Example transferring an SSH key
1. Check hash of key : `md5sum id_rsa`
2. Encode key : `cat id_rsa | bas`