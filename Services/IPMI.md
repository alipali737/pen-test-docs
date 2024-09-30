```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Intelligent Platform Management Interface* (*IPMI*) is a set of standardised specifications for hardware-based host management systems. Acts autonomously and works independent of the hosts BIOS, CPU, Firmware, or OS. 

Manage and monitor systems even if they are off or unresponsive. Acts as a direct network connection to the system's hardware (not requiring a OS shell). Typically used for:
- Modify BIOS settings before OS boot
- When a host is fully powered down
- Access to a host after a system failure

Can also monitor system diagnostics (temps, speeds, power etc), additionally it can query information, hardware logs, and alerting using SNMP. The host can be powered off but the IPMI module needs power and a LAN connection.

**Standard Port:** 
- 623/udp

**Version Names:** 

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
To function, an IPMI requires the following:
- *Baseboard Management Controller* (*BMC*) - A micro-controller.
- *Intelligent Chassis Management Bus* (*ICMB*) - An interface that permits communication from one chassis to another.
- *Intelligent Platform Management Bus* (*IPMB*) - Extends the BMC
- *IPMI Memory* - Memory unit for the system (logs, repo data etc)
- *Communications Interfaces* - Local system interfaces, serial and LAN interfaces, ICMB and PCI Management Bus

## Configuration
Systems that use the IPMI protocol are BMCs. These are typically embedded as ARM systems running Linux and are connected directly to the host's motherboard. Many motherboards have BMCs built in, but can also be added through PCI.

## Potential Capabilities
- 

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
### Nmap Scripts
- 