```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
A very common situation is when we have compromised a reachable host from our attack machine but aren't able to access any other targets from our machine. This is where a *pivot host* is useful for further accessing machines connected to our compromised one that we can't reach directly from our attack host.

## Pivoting
Pivoting is *moving to other networks through a compromised host to find more targets on different network segments*. The goal of pivoting is to defeat segmentation (both physically and virtually) to access an isolated network.
> Pivoting is slightly different to Lateral Movement as it works to move to other networks whereas Lateral Movement is movement within the same network.

On any new compromised host we should always check:
- Our privilege level
- Any network connections
- Potential VPN or remote access software

If a host has more than one network adapter, we can likely use it to move to another network segment.
> Some common names a pivot host might also be called:
> - Proxy
> - Foothold
> - Beach Head System
> - Jump Host

## Tunneling
Tunnelling is when we *encapsulate traffic in another protocol and route traffic through it*. VPNs are an example of tunnelling. This is particularly useful for evading detection systems where we need to discretely pass traffic in/out of a network (eg. using HTTPS to mask our C2 traffic). 