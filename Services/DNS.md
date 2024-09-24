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

SecurityTrails provides a short [list](https://securitytrails.com/blog/most-popular-types-dns-attacks) of the most popular attacks on DNS servers

**Standard Port:** 
- Zone transfers typically : *53/tcp*

**Version Names:** 

| service name | releases link                      | notes                                                                                                     |
| ------------ | ---------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Bind9        | [Bind9](https://www.isc.org/bind/) | Common Linux DNS server - [CVEdetails](https://www.cvedetails.com/product/144/ISC-Bind.html?vendor_id=64) |
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
- *SOA* : information about DNS zone and email address for admin contact (it will return as `name.domain` so you should replace the `.` with an `@`)
## Configuration
All DNS servers work with three different types of configuration files:
1. local DNS configuration files
2. zone files
3. reverse name resolution files

[Bind9](https://www.isc.org/bind/) is a often used Linux-based DNS server. `named.conf` is its local configuration:
- `named.conf.local` : zone entries for the individual domains
- `named.conf.options` : general settings
- `named.conf.log`

```shell
$ cat /etc/bind/named.conf.local

zone "domain.com" {
	type master;
	file "/etc/bind/db.domain.com";
	allow-update { key rndc-key };
};
```

A *zone file* is a text file that describes a DNS zone with the BIND file format. Typically a zone is for one domain only (exceptions are ISP and public DNS servers). Each zone has its own file. It must contain exactly one *SOA* record and at least one *NS* record. If there is a syntax error, a DNS server will respond with *SERVFAIL* and considers the zone to not exist.
```BIND
server1    IN    A    10.0.9.5
server2    IN    A    10.0.9.7

ftp        IN    CNAME    server1
mail       IN    CNAME    server2
```

A *reverse name resolution zone file* eg. `/etc/bind/db.10.0.9` must exist to be able to obtain an IP from a *FQDN*. This file maps the final octet of an IP to a respective host using the PTR record.
```BIND
5    IN    PTR    server1.domain.com
7    IN    MX     mail.domain.com
```

### Zone Transfers
Transfer of zones to another DNS server, typically over *53/tcp*. Abbreviated to *Asynchronous Full Transfer Zone* (*AXFR*).

## Potential Capabilities
- Link computer names & IP addresses
- Determine services associated with a domain
- Identify which computer serves a particular service by examining DNS queries (eg. email server)

## Enumeration Checklist

| Goal                                                     | Command(s)                                                         | Refs |
| -------------------------------------------------------- | ------------------------------------------------------------------ | ---- |
| Discover nameservers for a domain                        | dig ns [domain] @[target DNS server IP]<br><br>host -t ns [domain] |      |
| Check if there is a version entry with a CHAOS TXT query | dig CH TXT version.bind [IP]                                       |      |
| Show all available records that can be disclosed         | dig any [domain] @[target DNS server IP]                           |      |
### Nmap Scripts
- 