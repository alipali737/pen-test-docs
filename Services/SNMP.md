```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Simple Network Management Protocol* (*SNMP*) was created to monitor network devices. It can handle configuration tasks and change settings remotely. SNMP-enabled hardware includes routers, switches, servers, IoT devices etc, these can be queried and controlled using this protocol. *SNMPv3* is the current version which increases its security but also its complexity.

### SNMPv1
- Still used in smaller networks.
- Retrieve information, configure devices, and provides traps
- No built-in authentication mechanism (doesn't support encryption)

### SNMPv2
- Version `v2c` is the community-based SNMP
- Has some extended features
- The [[SNMP#Community Strings|community string]] is only transmitted in plain text, meaning it has no built-in encryption

### SNMPv3
- Authentication with username & password added
- Transmission encryption (via pre-shared key / symmetric encryption)
- Significantly more config options than `v2c` which could further introduce misconfigurations

**Standard Port:** 
- 161/udp : data and control commands
- 162/udp : the SNMP server sends *traps* which are packets triggered by an event (not explicitly requested by a client)

**Version Names:** 

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
- Data and control commands can be sent from a client to a SNMP server on port *161/udp* to control and configure the device.
- Sometimes, the SNMP will send so-called *traps* back to a client via port *162/udp*. These packets are sent because of a certain event triggering on the device rather than a client requesting them.

### MIB
*Management Information Base* (*MIB*) is an independent format for storing device information and enables cross communication between devices and manufacturers. It is a text file that contains all queryable SNMP objects of a device, listed in a standardised tree hierarchy.

It must contain at least one *Object Identifier* (*OID*), which, in addition to the mandatory *unique address* and a *name*, also provides information about the *type*, *access rights*, and *description*.

MIB files are written in *Abstract Syntax Notation One* (*ASN.1*) (an ASCII based text format). They don't contain actual data but reference where to find the data, what it looks like etc.

### OID
An *Object Identifier* represents a node in a hierarchical namespace. OIDs consist of integers and are concatenated by dot notation (eg. `1.2.3`). Many nodes in the OID tree only serve as reference to the items below them (eg. `1.2.3` is the only node that can explain `1.2.3.4`)

### Community Strings
They are like passwords that can determine whether the requested information can be viewed or not (kinda password + access control). Many organisations use *SNMPv2* as transitioning to *SNMPv3* is very complex. This means that a lack of knowledge can cause misconfigurations & the lack of encryption on the transmission of the string can cause it to be intercepted.

## Configuration
Configured by */etc/snmp/snmpd.conf* - [manpage](http://www.net-snmp.org/docs/man/snmpd.conf.html)
Contains IPs, ports, MIBs, OIDs, authentication, and community strings

### Dangerous Settings
- `rwuser noauth` : provides full access to the OID tree without authentication
- `rwcommunity <community string> <IPv4 address>` : Provides full OID tree access regardless of where the requests are sent from.
- `rwcommunity6 <community string> <IPv6 address>` : Same as above but uses IPv6

## Potential Capabilities
- Gain information about a device's configuration settings
- Modify the configuration of a device

## Enumeration Checklist

| Goal                      | Command(s)                                                                                                            | Refs |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------- | ---- |
| SNMP enumeration commands | snmpcheck -t [ip] -c [community string (default: public)]<br><br>snmpwalk -c public -v2c [ip]<br><br>snmpenum -t [ip] |      |
| Enum community string     | onsixtyone -c [wordlist] [ip]                                                                                         |      |
| Brute force OIDs          | braa [community string]@[ip]:.1.2.3.*                                                                                 |      |
### Nmap Scripts
- 