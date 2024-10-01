```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Windows Remote Management* (*WinRM*) uses the *Simple Object Access Protocol* (*SOAP*) to establish connections to remote hosts and their applications. It is a simple command line protocol.

*Windows Remote Shell* (*WinRS*) allows you to execute commands on the remote system.

Services like remote sessions using PowerShell and event log merging require *WinRM*.

**Standard Port:** 
- 5985/http
- 5986/https
- Previously used 80 & 443 but these are often blocked.

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works


## Configuration
- From Windows 10, it must be explicitly enabled and configured.
- Enabled by default starting with the Windows Server 2012, but must first be configured for older server and client versions (+ firewall configurations needed). 

## Potential Capabilities
- 

## Enumeration Checklist

| Goal                    | Command(s)                                                                         | Refs |
| ----------------------- | ---------------------------------------------------------------------------------- | ---- |
| Footprinting            | nmap [ip] -sV -sC -p5985,5986                                                      |      |
| Test a WinRM connection | *(powershell)* Test-WSMan <br><br>*(linux)* evil-winrm -i [ip] -u [user] -p [pass] |      |
### Nmap Scripts
- 