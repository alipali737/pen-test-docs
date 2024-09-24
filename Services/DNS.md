```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Domain Name System* (*DNS*) converts readable names (domains) to IP addresses. It is mainly unencrypted therefore devices on the local WLAN and ISPs can spy on DNS queries. *DNS over TLS* (*DoT*) or *DNS over HTTPS* (*DoH*) can be used for encryption. Alternatively the *DNSCrypt* protocol can encrypt traffic between the client and name server.

**Standard Port:** 

**Version Names:** 

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
There are several types of DNS servers used worldwide for the globally distributed DNS:

- *DNS Root Server* : Responsible for top-level domains (TLDs). Only requested if name server doesn't respond. `ICANN` coordinates the work of the root name servers.
- *Authoritative Nameserver* : They hold authority for a particular zone, only answering queries from their area. If it cannot answer a query, the root name server takes over.
- *Non-authoritive Nameserver* : Not responsible for any particular DNS zone. Collect information on DNS zones themselves through recursive or iterative DNS querying.
- *Caching DNS Server* : Cache information from other name servers for a specific period (duration determined by authoritative nameserver).
- *Forwarding Server* : Forward DNS queries to another DNS server.
- *Resolver* : Not authoritative DNS servers but perform name resolution locally in the computer or router.

Example Flow:
1. client asks a *resolver* for the IP of `example.com`.
2. the *resolver* checks if it is in the *caching DNS server*, if not, it queries the *root server*.
3. the *root server* returns the IP address of the `.com` TLD nameserver.
4. the TLD nameserver, returns the IP of the *authoritative nameserver* for `example.com`.
5. the *resolver* then queries the *authoritative nameserver*, which provides the IP for `example.com`.
6. the *resolver* then caches the result and sends it back to the client.

- A *forwarding server* may be used to pass the query to an upstream resolver.
- A *non-authoritative nameserver* may respond from cache if it has the needed information.

There are several types of DNS records:
- *A* : returns an IPv4 address
- *AAAA* : returns an IPv6 address
- *MX* : returns the responsible mail server
- *NS* : returns the DNS servers (nameservers)
- *TXT* : all-router can contain various information
- *CNAME* : alias for another domain name
- *PTR* : reverse lookup (converts IP to domain name)
- *SOA* : information about DNS zone and email address for admin contact
## Configuration


## Potential Capabilities
- Link computer names & IP addresses
- Determine services associated with a domain
- Identify which computer serves a particular service by examining DNS queries (eg. email server)

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
### Nmap Scripts
- 