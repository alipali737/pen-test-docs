```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[Link-Local Multicast Name Resolution](https://datatracker.ietf.org/doc/html/rfc4795) enables hosts to perform name resolution without conventional DNS. It basically asks hosts on the local network if they know the resolution for a certain name. It still maintains the same formats and standards as DNS but as its only link-local, it cannot substitute for DNS.

When LLMNR fails, NBT-NS (137/udp) will be used to identify hosts via their `NetBIOS name` instead.

**Standard Port:** 
- 5355/udp

## How it works


## Configuration


## Potential Capabilities
- 

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
### Nmap Scripts
- 