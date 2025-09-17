```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Wireshark
[Wireshark](https://www.wireshark.org/) is a tool for analysing packets in real-time. Its [filter engine](https://www.wireshark.org/docs/man-pages/wireshark-filter.html) can let us search through traffic for specific data:

| Filter String                              | Description                                                                               |
| ------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `ip.addr == [target]`                      | Filters packets with a specific destination IP                                            |
| `tcp.port == [port]`                       | Filters packet with a specific port                                                       |
| `http`                                     | Filters for HTTP traffic                                                                  |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Filters SYN packets (TCP handshake), useful for detecting scanning or connection attempts |
| `icmp`                                     | Filters for ICMP packets, useful for recon or network issues                              |
| `http.request.method == "POST"`            | Filters for HTTP POST requests. This could have unencrypted sensitive data                |
| `tcp.stream eq 53`                         | Filters for a specific TCP stream. Helps track conversations between two hosts            |
| `eth.addr == [MAC]`                        | Filters packets from/to a specific MAC address                                            |
| `ip.src == [src] && ip.dst == [dst]`       | Filters traffic between two specific IP addresses                                         |
We can also use display filters to search for string eg. `http contains passw`.

## Pcredz
[Pcredz](https://github.com/lgandx/PCredz) is another tool that can be used to extract credentials from live traffic or network packet captures (`.pcapng`). It targets:
- Credit card numbers
- POP credentials
- SMTP credentials
- IMAP credentials
- SNMP community strings
- FTP credentials
- Credentials from HTTP NTLM/Basic headers, as well as HTTP Forms
- NTLMv1/v2 hashes from various traffic including DCE-RPC, SMBv1/2, LDAP, MSSQL, and HTTP
- Kerberos (AS-REQ Pre-Auth etype 23) hashes

Pcredz can be run by either cloning the repo and installing the deps, or running the docker container - [Install](https://github.com/lgandx/PCredz?tab=readme-ov-file#install)
```bash
python3 ./Pcredz -f demo.pcapng -t -v
```