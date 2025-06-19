```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 4 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
The purpose of this phase is to identify any information that can give us a *lay of the land* within the domain's configuration. It could be looking for leaked information, breach data, username formats etc. We could potentially go even deeper and look for leaked code/repos, documents with internal links, or remotely accessible sites. Any information that can give us additional knowledge for attacking the domain.

## What to look for
- *IP Spaces* : Valid ASN (collection of addresses) for our target, netblocks in use for the public-facing infrastructure, cloud presence and the providers, DNS records etc ([[Enumeration#Infrastructure-based Enumeration]])
- *Domain Information* : Based on IP, DNS, and site registration data. Who administers the domain? Subdomains? Publicly accessible domain services? (Mail, DNS, Websites, VPNs etc). What defences are in place? (SIEM, AV, IPS/IDS etc).
- *Schema Format* : Organisation emails, AD usernames, password policies? Any information we can use to guess usernames?
- *Data Disclosures* : Publicly accessible data disclosures (`.pdf`, `.ppt`, `.docx`, `.xlsx`, etc). Any documents that can give us information on the intranet configuration and services? (Sites, Shares, User metadata, critical software, hardware, etc)
- *Breach Data* : Any publicly released usernames, passwords, or other critical information for a foothold

## Where to look
- *ASN / IP Registrars* : [IANA](https://www.iana.org/), [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/)
- *Domain Registrars & DNS* : [Domaintools](https://www.domaintools.com/), [PTRArchive](http://ptrarchive.com/), [ICANN](https://lookup.icann.org/lookup), [viewdns.info](https://viewdns.info/), manual DNS record requests ([[DNS]]) against the domain in question or against well known DNS servers, such as `8.8.8.8`.
- *Social Media* : Searching LinkedIn, X, Facebook, or the regions major social media sites, blogs, and news to gain any relevant information on the organisation. Job listing can also give away key information about their IT structure.
- *Public-Facing Company Websites* : Often the organisation's own website can be a gold mine: News articles, embedded documents, "About us", and "Contact Us" pages
- *Cloud & Dev Storage Spaces* : [GitHub](https://github.com/), [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Google searches using "Dorks"](https://www.exploit-db.com/google-hacking-database) Tools like [Trufflehog](https://github.com/trufflesecurity/truffleHog) and sites like [Greyhat Warfare](https://buckets.grayhatwarfare.com/) are fantastic resources for finding these breadcrumbs.
- *Breach Data Sources* : [HaveIBeenPwned](https://haveibeenpwned.com/) to determine if any corporate email accounts appear in public breach data, [Dehashed](https://www.dehashed.com/) to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication.

## Initial Enumeration of an AD Domain
**Looking for key information**:
- *AD Users* : can be used later for password spraying
- *AD Joined Machines* : Domain controllers, workstations, file, database, web and mail servers etc
- *Key Services* : Kerberos, NetBIOS, LDAP, DNS, SMB etc
- *Vulnerable hosts and services* : Anything that could be a quick win for a foothold

### Step 1 : Identify Hosts
#### Network Packet Inspection (Passive)
[[Wireshark]] and network inspectors like [[TCPDump]] allow us to listen to the network and gain information on its setup. `pktmon.exe` can be found on most windows 10 systems and can be used for a similar purpose.
> Make sure to check you are using the right interface that is connected to the internal network (`ifconfig/ipconfig`)
```bash
sudo -E wireshark
sudo tcpdump -i <interface>
```
> This is particularly important in black-box tests
- *What hosts are communicating?* : potential targets
- *What types of traffic is being used?* : services that are being used
- [[Network Addressing#Address Resolution Protocol (ARP)|ARP]], [Multicast DNS (MDNS)](https://en.wikipedia.org/wiki/Multicast_DNS), and other [layer two](https://www.juniper.net/documentation/us/en/software/junos/multicast-l2/topics/topic-map/layer-2-understanding.html) packets can quickly give away hosts
Many of these tools can save traffic in the `PCAP` format (*which can be viewed in wireshark*) so its a good idea to save any traffic you view to review it again later of add to a report.

[[Responder]] is a tool for listening, analysing, and poisoning a variety of protocols (incl. [LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution), [[SMB & RPC|NBT-NS]], and [MDNS](https://en.wikipedia.org/wiki/Multicast_DNS)).
![[Responder#Analyse only mode]]

#### ICMP Pings (Active)
> ICMP packet responses are often blocked by windows defender, in this case, a full TCP scan must be performed instead using [[Nmap#Host Discovery]] but this will take a while.

These checks involve actually sending traffic on the network and are therefore active enumeration.
[Fping](https://fping.org/) is like the `ping` command but provides some additional utilities, one of which is the ability to give it a host list. ICMP is not perfect but will give an initial idea of which hosts are responding.

```bash
fping -asgq <CIDR network>
```
> *a* : show targets that are alive
> *s* : print the stats at the end
> *g* : generate a target list from a CIDR network
> *q* : quiet - don't show results for each target (only shows compiled results at the end)

[[Nmap]] can also be used for this purpose of sending ICMP packets for active host identification
```bash
sudo nmap <CIDR network> -sn -PE --disable-arp-ping
```
> *-sn* : perform a ping sweep (for host identification)
> *-PE* : send ICMP packets
> *--disable-arp-ping* : by default nmap uses ARP packets to identify hosts

#### Nmap Scanning (Active)
[[Nmap]] is an extremely powerful tool for network manipulation and recon, it can be very loud though (depending on performance profile & features used). Once a list of targets has been identified, we can enumerate these hosts further to determine services running on them. This could present valuable information, critical hosts, and identify potentially vulnerable hosts to probe later.

For AD domains, its important to focus on common services such as [[DNS]], [[SMB & RPC]], [[LDAP]], and [[Kerberos]] etc.
```bash
sudo nmap -v -A -iL hosts.txt -oN ~/Scans/host-enum
```
> this will perform an aggressive scan on the top 1000 common ports on each of the hosts and save the results

### Step 2 : Identifying Users
#### Kerbrute - Internal AD Username Enumeration
[[Kerbrute]] is a stealthy domain account enumeration tool. Kerberos pre-authentication failures do no trigger logs or alerts so its really good for a stealthy approach.
