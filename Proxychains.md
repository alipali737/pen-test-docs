```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Proxychains is a tool that is capable of redirecting TCP connections through TOR, SOCKS(4/5), and HTTP/HTTPS proxy servers. It also allows for chaining multiple proxy servers together. Utilising proxy servers additionally hides our IP address from the receiving host as it will only see the IP address of the pivot host.

## Installation
```

```

## Documentation
**Cheatsheet:** 
**Website:** 
## Usage
### Configuration
To setup a new proxy, we need to add it to the `/etc/proxychains.conf`
```sh
# This will route all traffic used with proxy chains to localhost 9050 (which could be setup to connect externally with SSH)
socks4 127.0.0.1 9050
```
> For SSH connection setup, see [[Pivoting, Tunnelling, and Port Forwarding#SSH dynamic port forwarding with SOCKS]]

### Redirecting a tool's packets with proxychains
```sh
$ proxychains [tool]

$ proxychains nmap -v -sn 10.10.14.0/24
<..SNIP..>
|S-chain|-<>-127.0.0.1:9050-<><>-10.10.14.2:80-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-10.10.14.5:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-10.10.14.6:80-<--timeout
<..SNIP..>
```
> When using [[Nmap]], we must use a `full TCP connect scan` as proxychains cannot understand partial packets (`eg. a steath scan : -sS`).

