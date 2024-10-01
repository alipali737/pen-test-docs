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
- **Password** : A password is requested from the client.
- **Public-key** : Server sends cert to client to verify (prevents MITM), server creates a cryptographic problem with the public-key and the client decrypts it and returns the solution. 
- **Host-based** : Public-key but also only allows specific hosts to connect.
- **Keyboard** & **Challenge-response** : Like password by default but can be configured to have multiple challenges (eg. could also include 1-time pass etc)
- **GSSAPI** : Single sign on. Requires Windows AD or an IPA Server (Identity, Policy, and Authentication - linux equivalent to AD)

## Configuration
- */etc/ssh/sshd_config*
- [SSH Hardening Guide](https://www.ssh-audit.com/hardening_guides.html)

### Dangerous Settings
- `PasswordAuthentication yes`
- `PermitEmptyPasswords yes`
- `PermitRootLogin yes`
- `Protocol 1` : uses outdated version of encryption
- `X11Forwarding yes` : allows X11 forwarding for GUI applications (RDP basically)
- `AllowTcpForwarding yes` : allow forwarding of TCP ports
- `PermitTunnel` : allows tunnelling
- `DebianBanner yes` : displays a specific banner when logging in (info disclosure)
## Potential Capabilities
- Gain access to a remote system via a shell
- Priv escalation & footholding

## Enumeration Checklist

| Goal                                                    | Command(s)                                            | Refs                                             |
| ------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------ |
| Identify configurations, general info, encryption algos | ssh-audit.py [ip]                                     | [ssh-audit](https://github.com/jtesta/ssh-audit) |
| View authentication methods                             | ssh -v [user]@[ip]                                    |                                                  |
| Password brute force                                    | hydra -L [logins.txt] -P [passwords.txt] [target] ssh |                                                  |
| Shell Shock Exploit                                     | ssh -i bob bob@[ip] '() { :;}; /bin/bash'<br>         |                                                  |
### Nmap Scripts
- ssh-auth-methods
- ssh2-enum-alogs
- ssh-brute