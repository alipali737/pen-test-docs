```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Virtual Hosts vs Subdomains
A virtual host allows web servers to distinguish between multiple websites or applications sharing the same IP address. It utilises the `HTTP Host` header.

The key difference between *virtual hosts* and *subdomains* is their relationship to *DNS* and the web server's configuration.
- *Subdomains* : These extend a base domain, typically having their own DNS records, pointing to the same IP as the base or a different one. These can be used to organise different sections or services of a website.
- *Virtual Hosts* (*VHosts*) : These are configured in the web server itself, allowing for multiple websites or applications to be hosted on a single server. These can be top level domains (eg. `example.com`) or subdomains (eg. `dev.example.com`). However each vhost has its own separate config, enabling more precise controls.
> If a VHost doesn't have a DNS record, you can still access it via the `/hosts` file (bypassing DNS).
### VHost Fuzzing
This technique uses wordlist brute-forcing to enumerate public and private VHosts and Subdomains. This can reveal hostnames that aren't intended for the public or are only internally accessible.