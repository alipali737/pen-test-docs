```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Server Message Block* (*SMB*) is a client-server protocol for regulating access to shared files, directories, or other resources (printers etc) on a network. 
> Can also be used to communicate between system processes.

Primarily used in windows, but the *Samba* project makes SMB available on Linux and Unix, enabling cross-platform communication via SMB.

**Standard Port:** 
- SMB : *137-139*/tcp
- CIFS : *445*/tcp

**Version Names:** 

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
A client must establish a connection with an SMB server application before any access can be provided, this is done with a TCP handshake.

An SMB server can then provide arbitrary parts of its local file system as shares. *Access Control Lists* (*ACLs*) are used to control the shares (Not the underlying file permissions, that is [[Windows#NTFS vs Sharing Permissions|NTFS]]).
#### Samba
Samba implements the *Common Internet File System* (*CIFS*) protocol. It is a specific implementation of the SMB protocol (like a dialect), created by Microsoft. It allows connections with newer Windows systems.

When passing SMB commands over Samba to an older NetBIOS service, it usually connects over TCP ports *137-139*, but CIFS only uses *445*.
## Potential Capabilities
- 

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
