```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
An encrypted direct connection that allows a shell to be created on a remote machine. It is primarily designed for Linux & MacOS but applications can be installed on Windows to use it.

*SSH-2* is a more advanced version of *SSH-1* in encryption, speed, stability, and security. *SSH-1* is vulnerable to a *MITM* attack.

**Standard Port:** 
- 22/tcp

| service name | releases link                           | notes |
| ------------ | --------------------------------------- | ----- |
| OpenSSH      | [OpenBSD SSH](https://www.openssh.com/) |       |
## How it works
### OpenSSH Auth Methods
- **Password** : A password for the user is given
- **Public-key** : Server sends cert to client to verify (prevents MITM), server creates a cryptographic problem with the public-key and the client decrypts it and returns the solution. 
- **Host-based**
- **Keyboard**
- **Challenge-response**
- **GSSAPI**

## Configuration


## Potential Capabilities
- 

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
### Nmap Scripts
- 