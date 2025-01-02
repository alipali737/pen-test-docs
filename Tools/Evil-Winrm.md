```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
A [[WinRM]] shell for pentesting, written as a Ruby gem. It has a variety of features (Load in-memory, Pass-the-hash, File uploads etc) that can be used to interact with windows systems. It utilises the [Powershell Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/602ee78e-9a19-45ad-90fa-bb132b7cecec) (*MS-PSRP*) for its communication.

## Installation
```
sudo gem install evil-winrm
```

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/Hackplayers/evil-winrm
## Usage
```sh
evil-winrm -i <target-ip> -u <username> -p <password>
```

### Pass-the-Hash
PtH can be achieved by using the `-H` flag instead of a password
```sh
evil-winrm -i <target-ip> -u <username> -H <hash>
```