```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
The *Meterpreter* payload is a specific type of multi-faceted payload. It utilises DLL injection to ensure a stable, persistent across reboots connection. It has a variety of features built in such as key loggers, hash collection, tapping etc. It runs only in-memory so it is harder to find any forensic traces. We can also load and unload additional scripts and plugins dynamically. It also uses an AES-encrypted link over the socket for secure communication.

## Installation
Meterpreter is a payload that can be used through the [[Metasploit]] framework. Meterpreter comes in both staged (the normal) and stageless forms.
**Staged**:
1. `stage0` is a some shellcode that is executed as part of an exploit payload to open a connection to the attack machine (eg. `reverse_tcp`)
2. `stage1` is then downloaded into memory by stage0. This is where the `metsrv` DLL is read in and using [Reflective DDL Injection] it is read into memory without every being written to disk or registered with the host process. `metsrv` then takes over execution as our meterpreter service we are used too.
3. `stage2` is triggered by `metsrv` and brings in the first extension DLL: `stdapi`
4. `stage3` is the same as stage2, but brings in the final extension DLL: `priv`
Staged means we can hide `stage0` (which is very small `~360b` of shellcode) in many exploits, however the DLLs push up the size to `~1240kb`. This can be a major issue when working in a high latency or low bandwidth network. Additionally thats alot of downloading if you are working across a large network with many shells.

**Stageless**:
As the payload preparation is performed on our machine, the process is slightly different.
1. Metasploit copies the `metsrv` DLL into memory, overwriting the DLL's [DOS header](https://en.wikipedia.org/wiki/DOS_MZ_executable) with some shellcode that:
	1. Does some information gathering with GetPC
	2. Identifies an invokes the `ReflectiveLoader()` in `metsrv` for the Reflective DLL injection
	3. Identifies the pre-loaded extensions and invokes the `DllMain()` in `metsrv` with `DLL_METASPLOIT_ATTACH` which then takes over
	4. After `metsrv` exits, the shellcode also re-invokes `DllMain()` with `DLL_METASPLOIT_DETACH` which exits `metsrv` using the appropriate method.
2. Once the shellcode has been added, metasploit creates an in-memory payload buffer, writing each of the chosen extensions in along with its size.
3. Finally it adds a 32-bit null buffer which is what `metsrv` will look for to end its extension loading
The final payload looks like:
![[Pasted image 20241210132738.png]]
This can then be embedded in an exe file, encoded, and thrown into an exploit.
## Documentation
**Cheatsheet:** [[Using_The_Metasploit_Framework_Module_Cheat_Sheet.pdf]]
**Website:** 

## Meterpreter's Design Goals
### Stealthy
- It resides entirely in memory without anything stored on disk
- No new processes (it injects itself into the compromised process)
- It can migrate from one process to another
- AES encryption for all communications
- Little impact on the victim machine
- Very limited forensic evidence left behind
### Powerful
- Channelised communication between attack and victim machine
- Isolated communication between different channels
- Allows for AES encrypted channels
### Extensible
- Features can be augmented at runtime
- Extensions can be loaded over the network
- Modular structure means new features can be added without rebuilding
## Usage
### Useful Commands
Meterpreter uses a mix of linux & windows syntax command for faster interactions with targets
- *?* : opens the help menu
- *background* / *bg* : backgrounds the current [[Metasploit#Sessions|session]]
- *bgkill* : kill a background script
- *bglist* : list background scripts
- *bgrun* : run a script in the background
- *run* : run a script (not background)
- *channel* : displays channel information
- *close* : close a channel
- *exit* / *quit* : terminate the [[Metasploit#Sessions|session]]
- *guid* : get the GUID for the current session
- *secure* : (Re)negotiate TLV packet encryption on the session
- *db_nmap* : run nmap storing the results automatically in the [[Metasploit#Using databases in Metasploit|metasploit database]]
