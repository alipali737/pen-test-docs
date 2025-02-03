```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 4 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
`Ptunnel-ng` is a tunnelling tool that can support ICMP with [[Pivoting, Tunnelling, and Port Forwarding#SOCKS|SOCKS]]. It uses a client-server model to establish a tunnel that can then be used for proxying.

## Installation
```bash
git clone https://github.com/utoni/ptunnel-ng.git
```
> **IMPORTANT** - we need to make sure we have the same versions of GLIBC on our attack machine as the target has : `ldd --version`
## Documentation
**Cheatsheet:** 
**Website:** https://github.com/utoni/ptunnel-ng
## Usage
### Building Ptunnel-ng with Autogen.sh
```bash
sudo ./autogen.sh
```
> Once this is complete you will still need to [[Misc/File Transfer|Transfer]] the repo over to the pivot host but then you can use the client and server-side features.
#### Alternative approach for building a static binary
```bash
sudo apt install automake autoconf -y
cd ptunnel-ng/
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
./autogen.sh
```

### Running the Server on the Pivot Host
```bash
sudo ./ptunnel-ng/src/ptunnel-ng -r<pivot_host_ip> -R<remote_port>
# sudo ./ptunnel-ng -r p.p.p.p -R22
```

### Connect client to server from Attack Host
```bash
sudo ./ptunnel-ng -p<pivot_host> -l<local_port_to_use> -r<pivot_host> -R<remote_port>
# sudo ./ptunnel-ng -p p.p.p.p -l2222 -r p.p.p.p -R22
```

### Tunnelling an SSH connection through an ICMP Tunnel
```bash
# After setting up the above client / server configurations
ssh -p<local_port> -l<pivot_host_user> 127.0.0.1
```
> We can use this same tunnel (local port on localhost) to perform [[Pivoting, Tunnelling, and Port Forwarding#SSH dynamic port forwarding with SOCKS|dynamic port forwarding over SSH]]
> `ssh -D <dynamic_port> -p<local_ptunnel_port> -l<pivot_host_user> 127.0.0.1`
> We could then use [[Proxychains]] to create this proxy for a tool like [[Nmap]]



