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
### Basic Network Scan (Ping Sweeping)
```
nmap -sn [target range]
```
> Run as `sudo` for MAC addresses
> `-sn` disables port scanning on each target

A ping sweep is for target discovery, it sends ICMP packets to each address in the range and checks for responses.

### Target Service Scan
```
nmap -sV -sC -O -p- [target]
```
This will scan for service information and versions, run the default scripts, and try to guess the OS version, whilst scanning all ports 0-65535.

### TCP SYN Scan (Stealthier TCP alternative)
```
nmap -sS [target]
```
This scan type only performs a partial 3-way handshake, unlike the TCP Connect Scan. It does this by never sending the final ACK packet upon receipt of the SYN/ACK response from the server.



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
