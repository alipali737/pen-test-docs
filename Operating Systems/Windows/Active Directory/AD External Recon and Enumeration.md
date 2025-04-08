```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
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
- *Domain Registrars & DNS* : [Domaintools](https://www.domaintools.com/), [PTRArchive](http://ptrarchive.com/), [ICANN](https://lookup.icann.org/lookup), manual DNS record requests ([[DNS]]) against the domain in question or against well known DNS servers, such as `8.8.8.8`.
- *Social Media* : Searching LinkedIn, X, Facebook, or the regions major social media sites, blogs, and news to gain any relevant information on the organisation
- *Public-Facing Company Websites* : Often the organisation's own website can be a gold mine: News articles, embedded documents, "About us", and "Contact Us" pages
- *Cloud & Dev Storage Spaces* : [GitHub](https://github.com/), [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Google searches using "Dorks"](https://www.exploit-db.com/google-hacking-database)
- *Breach Data Sources* : [HaveIBeenPwned](https://haveibeenpwned.com/) to determine if any corporate email accounts appear in public breach data, [Dehashed](https://www.dehashed.com/) to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication.