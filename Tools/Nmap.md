```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary

Network Mapper (Nmap) is a tool for performing network scans and one of the most commonly used tools for network activities. Nmap supports an extensive scripting engine that can be used to extend the functionality of the tool and your scans.

Nmap by default conducts TCP (`-sT` or `-sS`) scans but can be requested to use UDP (`-sU`). 
> If a `STATE` appears as `filtered` that means there is a firewall only allowing connections from certain addresses.

[Zenmap](https://nmap.org/zenmap/) is a GUI utility for nmap.
## Installation
```
sudo apt install nmap
```

## Documentation
**Cheatsheet:** 
**Website:** 
## Usage
A basic scan uses the following format:
```shell
nmap {Scan Type(s)} {options} [target]
```

Nmap can take targets as IPv4/IPv6/URLs/Fully Qualified Domain Name (FQDN).

## Host Discovery
**Objective:** Determine what hosts are alive on a network that can be further enumerated
### Basic Network Scan (Ping Sweeping)
```
nmap -sn [target range]
```
> Run as `sudo` for MAC addresses
> `-sn` disables port scanning on each target

A ping sweep is for target discovery, it sends ICMP packets to each address in the range and checks for responses.
### Scan a specific list of hosts
By creating a file containing a list of IPs:
```
$ cat hosts.lst

10.0.9.1
10.0.9.2
10.0.9.3
10.0.9.7
```
We can use the `-iL hosts.lst` flag to only scan those targets.

### ARP & ICMP
When running with `-sn` to ping scan, by default Nmap will determine if a host is alive by an ARP reply:
```shell-session
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
```
This can be viewed by setting `--packet-trace`. If we also want to send an ICMP echo request we can use the `-PE`. The `-Pn` disables ICMP echo requests and presumes a host is alive.

If we just want to use ICMP we can use `--disable-arp-ping`. The information displayed in the response can give away information about the system. Many operating systems have different TTL values for ICMP echo responses. eg. in this we can see that the response received most likely came from a Windows machine (default of 128 TTL).
```shell-session
sudo nmap 10.129.2.18 -sn -PE --packet-trace --disable-arp-ping 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:12 CEST
SENT (0.0107s) ICMP [10.10.14.2 > 10.129.2.18 Echo request (type=8/code=0) id=13607 seq=0] IP [ttl=255 id=23541 iplen=28 ]
RCVD (0.0152s) ICMP [10.129.2.18 > 10.10.14.2 Echo reply (type=0/code=0) id=13607 seq=0] IP [ttl=128 id=40622 iplen=28 ]
...
```
#### Default ICMP Echo TTL
- Windows : 128
- Linux & MacOS : 64
- Network Devices : 255
## Host & Port Scanning
**Objectives:**
- Determine open ports and its services
- Service versions
- Information that each service provides
- Operating System & version

### Possible Port Responses
| State              | Description                                                                                                     |
| ------------------ | --------------------------------------------------------------------------------------------------------------- |
| open               | A connection (TCP, UDP, or SCTP) has been established with the port                                             |
| closed             | The returned TCP packet contains an `RST`(reset) flag, indicating the port is closed                            |
| filtered           | Cannot determine state, either no response was returned or an error returned                                    |
| unfiltered         | Only occurs with a TCP-ACK (`-sT`) scan meaning its accessible but cannot be determined if its open or closed   |
| open \| filtered   | No response was returned at all (possibly a firewall or filter protecting)                                      |
| closed \| filtered | Only occurs with a *IP ID idle* scan and it was impossible to determine if its closed or filtered by a firewall |
### Scan Types
#### TCP Scan
```
nmap -sT [target]
```
**Default for non-root scans**, attempts to perform a full TCP handshake to determine if it is open or closed.
#### TCP SYN Scan (Stealthier TCP alternative)
```
nmap -sS [target]
```
**Default when running as root**, this scan type only performs a partial 3-way handshake, unlike the TCP Connect Scan. It does this by never sending the final ACK packet upon receipt of the SYN-ACK response from the server. This is also faster than `-sT`. Considers a response with `SYN-ACK` as open, and `RST` as closed.

### Target Service Scan
```
nmap -sV -sC -O -p- [target]
```
This will scan for service information and versions, run the default scripts, and try to guess the OS version, whilst scanning all ports 0-65535.





### Automatic banner grabbing
This is an automated way of performing a similar grab to [[Netcat (nc)#Banner Grabbing|Netcat Banner Grabbing]].
```
nmap -sV --script=banner [target range]
```



---
## Creating Scripts in Lua

The anatomy of an NSE Script:
```lua
-- HEAD

-- RULES

-- ACTION
```

#### The HEAD
The `HEAD` section of the script contains meta information about your script

- `require` statements specify dependencies
```lua
local package1 = require "package1"
local package2 = require "package2"
```

- `description` is a variable that describes what the script does
```lua
description = [[
	Detailed description here!
]]
```

- `author`, `license`, and `categories` variables
```lua
author = "Your Name"

license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

categories = {"default", "safe"}
```

[We can see some common categories on the Nmap website](https://nmap.org/book/nse-usage.html). By adding the category `"default"`, this script would run when we use the `-sC` or `-A` configuration options. We’ll also say this script is `"safe"` because we aren’t planning to crash or hurt anything with our script!

#### The RULES
The `RULES` of the script is the portion of the code that determins if the script will run or not. For example, if port 80 isn't open, maybe we can't run out HTTP-specific script. In that case, we should terminate the script.

The script will always include one of:
- `prerule()` - This rule runs during the pre-scanning phase, before any hosts have been scanned. Useful for discovery scripts.
- `hostrule(host)` - This rule runs after each batch of hosts have been scanned.
- `portrule(host, port)` - This rule runs after each batch of ports have been scanned.
- `postrule()` - This rule is checked after the scan has completed. Useful for any scripts reviewing the full results of a scan.

#### The ACTION
This is where the actual functionality of the script is defined. If the RULE passes, then this section will be executed.

#### Hello World Script Example
```lua
-- HEAD
local nmap = require "nmap"

description = [[
  "Hello world script"
]]

author = "alipali737"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

-- RULES
portrule = function(host, port)
  local port_to_check = { number = 4000, protocol = "tcp" }
  local port_state = nmap.get_port_state(host, port_to_check)

  return port_state ~= nil and port_state.state == "open"
end

-- ACTION
action = function(host, port)
  return "Hello, port "..port.number.."!"
end
```
