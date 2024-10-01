```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
R-Services is a suite of services hosted to enable remote access or issue commands between Unix hosts over TCP/IP. *They were replaced by SSH*.

Much less common now but occasionally present on systems. Most used commercially by OS's such as Solaris, HP-UX, and AIX.

Consits of:
- `rpc` (*remote copy*)
- `rexec` (*remote execute*)
- `rlogin` (*remote login*)
- `rsh` (*remote shell*)
- `rstat`
- `ruptime`
- `rwho` (*remote who*)
- `rusers` (*remote users*)

**Standard Port:** 
- 512-514/tcp

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
- Use unencrypted connections to transmit information (susceptible to MITM attacks).
- It uses [Pluggable Authentication Modules (PAM)](https://debathena.mit.edu/trac/wiki/PAM) for user authentication but this can be overriden by trusted entries in */etc/hosts.equiv* or *.rhosts*

## Configuration


## Potential Capabilities
### Most abused commands

| Command  | Service Daemon | Port | Protocol |                                                                          Desc                                                                          |
| :------: | :------------: | :--: | :------: | :----------------------------------------------------------------------------------------------------------------------------------------------------: |
|  `rcp`   |     `rshd`     | 514  |   TCP    |                                            Copy a local file or directory. *no warning for file overwrites*                                            |
|  `rsh`   |     `rshd`     | 514  |   TCP    |            Opens a shell on the remote machine without a login procedure. Relies upon */etc/hosts.equiv* and *.rhosts* files for validation            |
| `rexec`  |    `rexecd`    | 512  |   TCP    | Run commands on a remote system, requires *username* and *password* through unencrypted socket. Auth is overriden by */etc/hosts.equiv* and *.rhosts*. |
| `rlogin` |   `rlogind`    | 513  |   TCP    |              Log into a remote host (like telnet but only for unix-like systems). Auth is overriden by */etc/hosts.equiv* and *.rhosts*.               |
> When a user is present in */etc/hosts.equiv* or *.rhosts* they are automatically granted access without further auth.
> 
> host.equiv format : `<hostname> <local username>`
> .rhosts format : `<username> <ip>`
## Enumeration Checklist

| Goal                                    | Command(s)                       | Refs |
| --------------------------------------- | -------------------------------- | ---- |
| Scan for R-Services                     | sudo nmap [ip] -sV -p512,513,514 |      |
| Login                                   | rlogin [ip] -l [user]            |      |
| View logged in users                    | rwho                             |      |
| View all logged in users on the network | rusers -al [ip]                  |      |
