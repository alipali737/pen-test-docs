```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Windows Management Infrastructure* (*WMI*) is the Microsoft implementation and extension of the *Common Information Model* (*CIM*), and core functionality of the *Standardised Web-Based Enterprise Management* (*WBEM*) for Windows.

WMI allows read and write access to almost all settings on Windows systems. It is a collection of programs and databases (A.K.A repositories). It can be access via *PowerShell*, *VBScript*, or the *Windows Management Instrumentation Console* (*WMIC*).

**Standard Port:** 
- 135/tcp : initial communication
- After connection, communication is moved to a random port

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works


## Configuration


## Potential Capabilities
- Read and write most windows settings

## Enumeration Checklist

| Goal                | Command(s)                               | Refs                                                                                     |
| ------------------- | ---------------------------------------- | ---------------------------------------------------------------------------------------- |
| Connect via wmiexec | wmiexec.py [user]:[pass]@[ip] "hostname" | [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) |

### Nmap Scripts
- 