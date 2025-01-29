```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunnelling tool written in Go. It uses HTTP through SSH for secured data transportation. Chisel can create a client-server tunnel connection in a firewall restricted environment. We can start a server on a compromised machine that listens on a specific port and forwards our traffic to the internal network through the tunnel.

## Installation
```
git clone https://github.com/jpillora/chisel.git
cd chisel
go build .
```
> Also requires Go to be installed to build the binary
## Documentation
**Cheatsheet:** 
- https://0xdf.gitlab.io/cheatsheets/chisel
- [IppSec's walkthrough using chisel](https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s) (includes, shrinking the binary size to prevent detection)
**Website:** https://github.com/jpillora/chisel
## Usage
### Start the chisel server on the compromised machine
```bash
./chisel server -v -p [port_to_listen_on] --socks5
```
> This lets us forward to any network interfaces the machine is connected too

### Connecting to the chisel server from the attack machine
```bash
./chisel client -v [pivot_host_ip]:[port] socks
```
> The logs output will tell us what local port the client is listening on, to send traffic, we can configure a tool like [[Proxychains]] to redirect to `socks5 127.0.0.1 [chisel_client_port]`.
> The default client listener port is `1080`.
> You will need to [[Proxychains#Configuration|configure proxychains]] to use this port & socks5.

### Reverse Pivot with Chisel
Sometimes a firewall will still block inbound connections so we won't be able to connect to our pivot host. To get around this we can make chisel form a reverse connection.
To enable this, add `--reverse` in the server start up command: `./chisel server -v -p [port] --reverse --socks5`.
Then in the client, add the `R:socks` options to denote the reverse connection: `./chisel client -v [pivot_host_ip]:[port] R:socks`.

The server will listen and accept connections, then they will be proxied through the client, which specified the remote. 

### Reduce the binary size
The binary for chisel is around 10MB, this can be quite large to transfer undetected.
```bash
ls -lh chisel 

-rwxr-xr-x 1 root root 10M Jan 27 06:47 chisel
```

Ippsec points out that this is 10MB, which is a large file to be moving to target in some environments. He shows how you can run `go build -ldflags="-s -w"` and reduce it to 7.5MB (where `-s` is “Omit all symbol information from the output file” or strip, and `-w` is “Omit the DWARF symbol table”). He also shows how to `upx` pack it down to 2.9MB if bandwidth is tight.