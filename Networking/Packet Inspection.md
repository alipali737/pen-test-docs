```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Stateless Inspection
- Each packet is inspected one at a time, independently of any other packet knowledge
- No session tables are maintained, no database of previous packets inspected
- Much faster than stateful inspection, no need to check databases

### What is inspected?
- Source IP address
	- Access Control List rule determins if an IP is allowed into the network or if dst IP is allowed to be accessed
- Destination port / service

### Use Cases
- To protect routing engine resources
- To control traffic going in or out your network
- For troubleshooting purposes when classifying packets
- To control traffic routing (through the use of routing instances)
- To perform QoS/CoS (marking traffic priorities)

## Stateful Inspection
- Each packet is inspected with knowledge of all the previous packets in that session

### Sessions
- A session contains all the packets exchanged between the parties in an exchange
- Contains:
	- Src IP & Port
	- Dst IP & Port
	- [Optional] Instance Identifyer
- A session ID can be used to locate the session information from the firewall packet database

```shell
$ show security flow session application telnet
Session ID: 57866, Policy name: intrazone-Juniper-SV/4, Timeout: 3394, Valid
In: 172.20.107.10:56290 --> 172.20.207.10:23;tcp, If: vlan.107, Pkts: 27, Bytes: 1568
Out: 172.20.207.10.23 --> 172.20.107.10:56290;tcp, If: lt-0/0/0.1, Pkts: 21, Bytes: 1543
```

## Using both Stateful & Stateless together
- Stateless inspection is performed first
- Then Stateful data is evaluated
