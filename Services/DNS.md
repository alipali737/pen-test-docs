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
- Normal use: *53/udp*
- Zone transfers typically : *53/tcp* (being used more and more in current times)

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

![[dns.svg]]

There are several types of DNS records:
- *A* : returns an IPv4 address
- *AAAA* : returns an IPv6 address
- *MX* : returns the responsible mail server
- *NS* : returns the DNS servers (nameservers)
- *TXT* : all-rounder can contain various information
- *CNAME* : alias for another domain name
- *PTR* : reverse lookup (converts IP to domain name)
- *SRV* : service record that defines a hostname and port for a specific service
- *SOA* : information about DNS zone and email address for admin contact (it will return as `name.domain` so you should replace the `.` with an `@`)
## The Hosts File
The `hosts` file (eg. `/etc/hosts`) is a file that maps hostnames & domains to IP addresses. It provides a manual method of domain name resolution that bypasses the DNS process. This can be particularly useful for development, troubleshooting, or blocking websites. They take immediate effect and don't need a system or service restart.
- *Linux* & *MacOS* : `/etc/hosts`
- *Windows* : `C:\Windows\System32\drivers\etc\hosts`

```
<IP address> <Hostname> [<Alias> ...]

127.0.0.1        localhost
192.168.1.10     devserver.local
```

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
Transfer of zones to another DNS server, typically over *53/tcp*. Abbreviated to *Asynchronous Full Transfer Zone* (*AXFR*). Zone files are usually stored over multiple servers for redundancy (with a master and slaves). The process to keep all these files in sync is zone transfer, and it uses the `rndc-key` for secure communication.

There is a *primary* & multiple *secondary* name servers. Modifications are made to the primary which then gets replicated to the secondary servers. The secondaries (at certain intervals) fetch the `SOA` record from the primary and compare serial numbers.
```shell
dig axfr [domain] @{nameserver}
```

1. Secondary DNS initiates a *Zone Transfer Request (AXFR)*.
2. Primary sends its *Start of Authority (SOA)* record, and secondary determine if its zone data is current.
3. Primary transfers all DNS records in the zone one by one.
4. Primary signals the transfer is complete.
5. Secondary acknowledges the primary server and closes the connection.

It is critical that access control is put in place as these transfers can leak sensitive information (subdomains, IPs, name server records etc).
### Brute-forcing Subdomains
We can brute force `A` records to detect subdomains:
```shell
for sub in $(cat [wordlist]);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

There are four steps to enumerating subdomains:
1. *Wordlist selection* : General purpose, targeted, or even custom wordlists can be used.
2. *Iteration and Querying* : Iterate through the word list, appending the word to the base domain eg. `example.com` -> `dev.example.com`.
3. *DNS Lookups* : Perform a DNS query on the subdomain and see if it resolves to an IP (typically `A` or `AAAA` records).
4. *Filtering and Validation* : If the subdomain is resolved, it will be added to a list of valid subdomains for further validation.

| Tool                                                    | Description                                                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [dnsenum](https://github.com/fwaeytens/dnsenum)         | Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.                 |
| [fierce](https://github.com/mschwager/fierce)           | User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.                |
| [dnsrecon](https://github.com/darkoperator/dnsrecon)    | Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.                     |
| [amass](https://github.com/owasp-amass/amass)           | Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources. |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.               |
| [puredns](https://github.com/d3mondev/puredns)          | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.                           |
| [gobuster](https://github.com/OJ/gobuster)              | Directory/File, DNS and VHost busting tool written in Go.                                                                       |
## Potential Capabilities
- Link computer names & IP addresses
- Determine services associated with a domain
- Identify which computer serves a particular service by examining DNS queries (eg. email server)

## DNS Tools
| Tool                       | Key Features                                                                     | Use Cases                                                                                       |
| -------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| *dig*                      | Versatile DNS lookup tool that supports various query types and detailed output  | Manual DNS queries, zone transfers, troubleshooting DNS issues, analysis of DNS records         |
| *nslookup*                 | DNS lookup tool primarily for `A`, `AAAA`, and `MX` records                      | Basic DNS queries, quick checks of DNS and mail server records                                  |
| *host*                     | Streamlined DNS lookup tool with concise output                                  | Quick checks of `A`, `AAAA`, and `MX` records                                                   |
| *dnsenum*                  | automated DNS enum tool, dictionary attacks, brute-force, zone transfers         | discovering subdomains and gathering DNS information                                            |
| *fierce*                   | DNS recon and subdomain enumeration with recursive search and wildcard detection | GUI for DNS recon, identifying subdomains and potential targets                                 |
| *dnsrecon*                 | Multiple DNS recon techniques and various output formats                         | Comprehensive DNS enumeration, identify subdomains, and gathering DNS records                   |
| *theHarvester*             | OSINT tool gathers from various sources, including DNS records (email addresses) | Collecting emails, employee info, and other data associated with a domain from multiple sources |
| Online DNS Lookup services | GUI for performing DNS lookups                                                   | Quick and easy lookups, doesn't require CLIs, check for availability or basic info              |
### Common dig Commands
- `dig [domain]` : default `A` record lookup for a domain
- `dig [domain] [type]` : specify the type of record to lookup
- `dig @[nameserver IP] [domain]` : query a specific name server
- `dig +trace [domain]` : full path of DNS resolution
- `dig -x [ip]` : reverse DNS lookup
- `dig +short [domain]` : concise output
- `dig +noall +answer [domain]` : displays answer only

### DNSEnum
A powerful cli written in Perl for DNS reconnaissance:
- *DNS Record Enumeration* : find records and config
- *Zone Transfer Attempts* : try to perform zone transfers to find misconfigurations
- *Subdomain Brute-Forcing* : brute force subdomains using a wordlist
- *Google Scraping* : scrapes google search results for additional subdomains
- *Reverse Lookup* : finds domains associated with an IP address
- *WHOIS Lookups* : performs WHOIS queries to find domain information

## Enumeration Checklist

| Goal                                                     | Command(s)                                                                                                                                                  | Refs                                                                |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| DNS Zone Transfer                                        | dig axfr [domain] @[nameserver]<br><br>*(win)* nslookup-> set type=any -> ls -d [domain]<br><br>fierce --domain [domain]                                    | <br><br><br><br>Enumerate root domain and search for zone transfers |
| DNS brute force                                          | dnsrecon -d [Target] -D [dnsmap wordlist] -t std --xml output.xml<br><br>dnsenum --dnsserver [IP] --enum -p 0 -s 0 -o subdomains.txt -f [wordlist] [domain] |                                                                     |
| Enumerate subdomains                                     | gobuster dns -w [wordlist] -d [domain]                                                                                                                      | [[DNS#Brute-forcing Subdomains]]                                    |
| Discover nameservers for a domain                        | dig ns [domain] @[target DNS server IP]<br><br>host -t ns [domain]                                                                                          |                                                                     |
| DNS IP lookups                                           | dig a [domain] @[nameserver]                                                                                                                                |                                                                     |
| DNS MX record lookup                                     | dig mx [domain] @[nameserver]                                                                                                                               |                                                                     |
| Check if there is a version entry with a CHAOS TXT query | dig CH TXT version.bind [IP]                                                                                                                                |                                                                     |
| Show all available records that can be disclosed         | dig any [domain] @[target DNS server IP]                                                                                                                    |                                                                     |
### General steps
1. Find all zones using:
	1. `axfr` (Zone Transfer) on the domain (if it is allowed)
	3. brute force if ZT isn't allowed (`dnsenum`)
2. `dig` or `dnsenum` any zones you find (for `dig` look for authority section with same name)

Sometimes a zone has an `allow-transfer` setting meaning it will only allow a transfer from a specific host, so we have to brute force instead.
### Nmap Scripts
- 