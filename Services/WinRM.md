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
*WinRM* is the Microsoft implementation of the [Web Services Management Protocol](https://docs.microsoft.com/en-us/windows/win32/winrm/ws-management-protocol) (*WS-Management*) network protocol. It is an XML-based protocol using *SOAP* for remote windows system management. It handles the communication between  [Web-Based Enterprise Management](https://en.wikipedia.org/wiki/Web-Based_Enterprise_Management) (*WBEM*) and the [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) (*[[WMI]]*), which can call the [Distributed Component Object Model](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0) (*DCOM*).

## Configuration
- From Windows 10, it must be explicitly enabled and configured.
- Enabled by default starting with the Windows Server 2012, but must first be configured for older server and client versions (+ firewall configurations needed). 

## Potential Capabilities
- Configuration of windows systems

## Enumeration Checklist

| Goal                      | Command(s)                                                                         | Refs             |
| ------------------------- | ---------------------------------------------------------------------------------- | ---------------- |
| Footprinting              | nmap [ip] -sV -sC -p5985,5986                                                      | [[Nmap]]         |
| Cracking user credentials | crackmapexec [proto] [target-ip] -u [user or userlist] -p [pass or passlist]       | [[CrackMapExec]] |
| Test a WinRM connection   | *(powershell)* Test-WSMan <br><br>*(linux)* evil-winrm -i [ip] -u [user] -p [pass] | [[Evil-Winrm]]   |
### Establish WinRM Session from Windows
```PowerShell
$password = ConvertTo-SecureString "[pass]" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("[domain]\[user]", $password)
Enter-PSSession -ComputerName [host] -Credential $cred
```

### Establish WinRM Session from Linux
![[Evil-Winrm#Usage]]