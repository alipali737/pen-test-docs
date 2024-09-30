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

The [flaw](http://fish2.com/ipmi/remote-pw-cracking.html) in the RAKP protocol in IPMI 2.0 means that before authentication takes place a salted hash (SHA1 or MD5) is sent to the client. This can be cracked and used to obtain the password for any user on the BMC. This "flaw" is a critical component of the IPMI specification so there is no direct fix. Using long, complex passwords or network segmentation can restrict access to the BMC. 

## Configuration
Systems that use the IPMI protocol are BMCs. These are typically embedded as ARM systems running Linux and are connected directly to the host's motherboard. Many motherboards have BMCs built in, but can also be added through PCI.

### Default Passwords

| Product         | User          | Pass                                                |
| --------------- | ------------- | --------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                              |
| HP iLO          | Administrator | random 8-char string of numbers & uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                               |
> HP iLO : `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u` tries all combinations.
## Potential Capabilities
- Gain physical-like capabilities over the system's motherboard (monitor, power, modify BIOS, reinstall OS etc)
- Many BMCs expose a web-based console, a CLI remote access protocol (eg. telnet or SSH), and port 623/udp for the IPMI protocol.

## Enumeration Checklist

| Goal               | Command(s)                                                                                                                                                              | Refs |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- |
| Version scan       | sudo nmap -sU --script=ipmi-version -p623                                                                                                                               |      |
| msf info scanner   | [IPMI Information Discovery (auxiliary/scanner/ipmi/ipmi_version)](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_version/)                              |      |
| msf Dumping hashes | [IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval (auxiliary/scanner/ipmi/ipmi_dumphashes)](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/) |      |
| Passcracking       | hashcat -a 0 -m 7300 --username [hashes] [wordlist]                                                                                                                     |      |
### Nmap Scripts
- ipmi-version