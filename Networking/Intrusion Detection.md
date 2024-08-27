```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Intrusion Detection System (IDS)
- Network security technology originally built for detecting vulnerability exploits against a target application or computer.
- Listen-only device
- Most often, the IDS is a dedicated server that is connected to a port on a switch.
- The switch forwards a copy of all traffic to the IDS for inspection
- Monitors traffic (looking for anomalous behaviour) and then notifies an administrator
- Cannot automatically take action to prevent a detected exploit from taking over the system
> Some modern IDS' can run scripts, eg. that send a command to block an IP address to the router

## Intrusion Prevention System (IPS)
- Network security/threat prevention technology that examines network traffic to detect and prevent vulnerability exploits.
- IPS sits inline in a network, meaning all traffic MUST pass through it first before it can then move on (this adds a delay to the traffic)
- Positioned right after an edge device, router or firewall (Some firewalls are designed to act like an IPS)
- Unlike an IDS, the IPS actively analyses packets, taking automated actions on all traffic flows that enter the network

| | IPS | IDS |
|-|-|-|
| Placement in the network infrastructure | Part of the direct line of communication (inline) | Outside direct line of communication (offline) |
| System Type | Active (monitors and automatically defends) and/or passive | Passive (monitors and notifies) |
| Detection mechanism | Statistical anomaly-based detection; Signature detection: Explit-facing signature, Vulnerability-facing signature | Anomaly based |

## IPS Defences
- Can automatically create an ACL to block traffic that has been identified as malicious
- In passive mode, it will just notify the admin

## Detection Methods
### Anomaly-Based
- Detect if a protocol's standards are not being followed
- eg. Lots of half opened TCP sessions, HTTP arrives with an unexpectedly long header or missing headers
### Signatures
- Contain a database of signatures that are malicious
- Patterns that can be found in the payload of traffic
### Host-Based IDS (H-IDS)
- Software based solutions installed on a host to defend it from attack
- Listens to the traffic being received by or sent from the endpoint, and takes action/alerts where needed
### Network-Based
- Hardware based
- IDS - sits on the side and received a copy of the traffic
- IPS - sits on the line and actively analyses traffic

## Firewall Filters
- Many modern firewall designs have a `Control Plane` and a `Forwarding Plane`
- The **Forwarding Plane** is responsible for all routing decisions, forwarding the packets on, policy evaluations, session matching etc
- The **Control Plane** runs the device operating system and holds the routing table, if this plane becomes unavailable the device can still forward traffic as the Plane's are separate