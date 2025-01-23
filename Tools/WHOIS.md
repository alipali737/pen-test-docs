```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
WHOIS is a widely used query and response protocol designed to access databases that store information about registered internet resources. You can determine details such as owners, contact, IPs, autonomous systems that are related to a domain name (like a phonebook for the internet).

It can be useful for:
- *Identifying Key Personnel* : Can reveal names, emails, phone numbers of responsible individuals. (Could be used for social engineering)
- *Discovering Network Infrastructure* : Technical details like name servers and IPs can provide clues about the target's network infrastructure. (Potential entry points and misconfigurations)
- *Historical Data Analysis* : Using [WhoisFreaks](https://whoisfreaks.com/) can reveal historical changes around the domain.

## Installation
```bash
sudo apt update
sudo apt install whois -y
```

## Documentation
**Cheatsheet:** 
**Website:** 
## Usage
```bash
$ whois inlanefreight.com

[...]
Domain Name: inlanefreight.com
Registry Domain ID: 2420436757_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.amazon
Registrar URL: https://registrar.amazon.com
Updated Date: 2023-07-03T01:11:15Z
Creation Date: 2019-08-05T22:43:09Z
[...]
```

Typically contains:
- *Domain Name* : The domain name itself (eg. example.com)
- *Registrar* : The company where the domain was registered (eg. GoDaddy, Namecheap)
- *Registrant Contact* : The person or organisation that registered the domain
- *Administrative Contact* : The person responsible for managing the domain
- *Technical Contact* : The person handling technical issues related to the domain
- *Creation and Expiration Dates* : When the domain was registered and when it expires
- *Name Servers* : Servers that translate the domain name to an IP address