```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[SocksOverRDP](https://github.com/nccgroup/SocksOverRDP) is a tool that uses *Dynamic Virtual Channels* (*DVC*) from Windows' Remote Desktop Service. DVC can tunnel packets over an RDP connection, this is how clipboard sharing and audio sharing works in RDP. This feature can also be used for arbitrary network packets, allowing us to tunnel custom packets through and use the system as a proxy (a tool like [[Proxifier]] can be used as the proxy server). 

## Installation
[SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/nccgroup/SocksOverRDP
## Usage
### Load SocksOverRDP.dll using regsrv32.exe
```batch
C:\...\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

### Connect via SocksOverRDP
1. Use `mstsc.exe` (windows' RDP feature) to connect to the internal target (*If RDP is slow, change the setting experience>performance>modem*)
2. When we connect, we should receive a dialog prompt saying that the SocksOverRDP plugin is enabled.

### Start the server on the target
1. Copy the `SocksOverRDP-Server.exe` (or the whole `.zip`) to the target
2. Start the `SocksOverRDP-Server.exe` with admin privileges on the target server and it will establish connection with our pivot host on (default)  `127.0.0.1:1080` (`netstat -antb | findstr 1080`)

### Establish the forwarding with our attack host
1. Use a tool like [[Proxifier]] on the pivot host to establish port forwarding to the local port `1080`