```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Remote Desktop Protocol* (*RDP*) is a protocol for accessing a windows system remotely. It transmits display and control commands via a GUI over an encrypted TCP connection.

**Standard Port:** 
- 3389/tcp
- 3389/udp

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
- Supports TLS/SSL but many windows systems don't insist it must be used. 
- By default the certificates are self-signed.
- It comes installed on windows by default. Activated using the *Server Manager*.
- Defaults to only allowing connections from hosts with [Network level authentication](https://en.wikipedia.org/wiki/Network_Level_Authentication) (*NLA*).

## Configuration


## Potential Capabilities
- Remote GUI access to a windows target

## Enumeration Checklist

| Goal                | Command(s)                                     | Refs                                                                                       |
| ------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------ |
| General Information | sudo nmap [ip] -sV -sC -p3389 --script rdp*    |                                                                                            |
| RDP security check  | sudo cpan<br>rdp-sec-check.pl [ip]<br>         | [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check)                       |
| RDP Bruteforce      | hydra -L [user_list] -P [pass_list] rdp://[ip] | [[Hydra]]<br>> this can cause account lockouts, so password-spraying attacks are preferred |
| Connect to an RDP   | xfreerdp /u:[user] /p:[pass] /v:[ip]           |                                                                                            |
> Nmap uses the cookie `mstshash=nmap` on RDP connections. This can be identified by threat hunters or EDRs that could result in us getting blocked.
### Nmap Scripts
- rdp-*
- rdp-enum-encryption
- rdp-ntlm-info