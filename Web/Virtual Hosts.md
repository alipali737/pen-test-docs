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
## Types of Virtual Hosting
- *Name-based Virtual Hosting* : Relies solely on the HTTP Host header. Doesn't require multiple IPs. Requires support from web server for name-based VH and can have limitations with certain protocols like SSL/TLS.
- *IP-Based Virtual Hosting* : Assigns a unique IP to each website hosted on a server, doesn't require the Host header and can be used with any protocol (better isolation between sites too). However multiple IPs are expensive and not scalable.
- *Port-Based Virtual Hosting* : Associate different websites with different ports. Not as common or user-friendly as name-based VH, and often requires the port to be specified in the URL.

## Virtual Host Discovery Tools

| Tool                                                 | Description                                                                               | Features                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| [[Gobuster]]                                         | ![[Gobuster#Summary]]                                                                     | Fast, supports multiple HTTP methods, can use custom wordlists |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Similar to Gobuster, but written in Rust. Known for its speed and flexibility.            | Supports recursion, wildcard discovery, and various filters.   |
| [ffuf](https://github.com/ffuf/ffuf)                 | Fast web fuzzer that can be used for virtual host discovery by fuzzing the *Host* header. | Customisable wordlist input and filtering options.             |
