```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
Important to understand the structure of the company, its services, processes, security measures, and third-party vendors it uses. Gaining a larger *overview of the company will allow us to understand our target better*.

Gather information from domains, IPs, accessible services etc. Once we know the client's infrastructure we can examine the individual services and protocols. Understand how customers, infrastructure, admins, and employees interact.
## Our Focus
**We want to find all the ways to the systems, not just to get in and exploit.**
**What can be exploited rather than actually exploiting the machine.**

## Questioning our Views
We can ask several questions to understand what we may be facing:
- **What can we see?**
	- *We can see that port 22 is open and running SSH*
- **What reasons can we have for seeing it?**
	- *It is a publicly exposed port, accessible from the internet by anyone.*
		- What else is publicly exposed? and why?
			- *Do they not have a company VPN? or why is machine not on it?*
- **What images does what we see create for us?**
	- *Remote work, potentially lax or inconsistent security controls for machines. Some things are publicly accessible*
- **What do we gain from it?**
	- *We know that we could have a route in if we find credentials for it*
- **How can we use it?**
	- *We could use this to gain access to an account (possibly escalate privs too)*
	- *Could gain sensitive information from the server*
- **What can we not see?**
	- *What other services are on this machine? what else is exposed and what is not?*
	- *What is the purpose of this machine? What is stored on it and why is it publicly accessible?*
	- *Can this machine talk with others?*
- **What reasons can there be that we do not see?**
	- *We don't have user credentials to access the server via SSH*
- **What image results for us from what we do not see?**
	- *This machine needs to be accessible from outside the corporate network for some reason, why? is this a intended?*

## Three Core Principles
1. There is always more than meets the eye. Consider all points of view.
2. Distinguish between what we can and cannot see
3. There is always ways to gain more information. Understand the target.

## Enumeration Methodology
![[enumeration-methodology.webp]]
There are three main categories: *Infrastructure-based Enumeration*, *Host-based Enumeration*, and *OS-based Enumeration*. This model is more of the general topics rather than specific instructions.
> Often there is a 'soft spot in the wall' that will allow us to progress further and gain more information, rarely do we actually need to force our way through.

> Layers 1 & 2 are primarily for external test situations and do not apply as thoroughly for internal test scenarios.

> OSINT could also be added as part of the Internet Presence layer
1. **Internet Presence** : Internet presence of the client and externally accessible infrastructure. *Find all possible target systems and interfaces we can test*
	1. Domains
	2. Sub-domains
	3. vHosts
	4. ASN
	5. Netblocks (blocks of IP addresses assigned to an organisation)
	6. IP Addresses
	7. Cloud Instances
	8. Security Measures
2. **Gateway** : Possible security measures to protect the company's external and internal infrastructure. *What are we dealing with, and what do we need to be careful of*
	1. Firewalls
	2. DMZ
	3. IPS/IDS
	4. Endpoint Detection & Response systems (EDRs)
	5. Proxies
	6. Network Access Control (NAC)
	7. Network Segmentation
	8. VPN
	9. Cloudflare
3. **Accessible Services** : Accessible interfaces and services that are hosted externally or internally. *Understand the reason and functionality of the target, and gain the necessary knowledge to communicate with it and exploit it for our purposes effectively*
	1. Service Type
	2. Functionality
	3. Configuration
	4. Port
	5. Version
	6. Interface
4. **Processes** : Internal processes, sources, and destinations associated with the services. *Understand the different processes, their tasks, data, source, and target. Understand the dependencies between them.*
	1. PID
	2. Processed Data
	3. Tasks
	4. Source
	5. Destination
5. **Privileges** : Internal permissions and privileges to the accessible services. *Identify permissions that have been overlooked, understand what is and is not possible.*
	1. Groups
	2. Users
	3. Permissions
	4. Restrictions
	5. Environment
6. **OS Setup** : Internal components and systems setup. *How the admins manage the systems and what sensitive data can be collect*
	1. OS Type
	2. Patch Level
	3. Network Config
	4. OS Environment
	5. Configuration Files
	6. Sensitive Private Files

## Infrastructure-based Enumeration
### Domain Information
- *Passive information gathering* to explore the internet presence of the client.
- Looking to gain any information on *technology stacks* or structures.
- *Company websites and services*, as well as *third-party recon tools*.
- *Understand the services offered* by the company and what we can see as a 'customer'.
#### SSL Certificates
- Potentially reveal sub-domains or DNS alt names
- Tools like [crt.sh](https://crt.sh/) can give us certificate logs that can reveal more information
![[SSL Certificates#Enumerating Subdomains Through CT Logs]]
It is important that we collect the IP addresses and ensure they are on our scope list. We can use the `host` command for this:
```shell
for i in $(cat subdomainlist); do host $i | grep "has address" | grep target.com | cut -d" " -f1,4; done
```
We can then run these IP addresses through a tool like [Shodan](https://www.shodan.io/) to find devices and services.

Additionally we can use a tool like `dig` to search DNS records for a domain.
```shell
dig any target.com
```

There are many types of records we could get but a few common ones:
- `A` : *IP address records* (likely these will already be known from prev steps)
- `MX` : *Mail server records*, can could gain valuable insights into the company's email service provider
- `NS` : *Name server records*, can be used to identify the hosting provider as most use their own name servers
- `TXT` : *Text records*, often contain verification keys for third-parties, and other security aspects of DNS ([SPF](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC](https://datatracker.ietf.org/doc/html/rfc7489), and [DKIM](https://datatracker.ietf.org/doc/html/rfc6376)).

### Cloud Resources
- Cloud storage resources are often misconfigured and require no auth
	- *S3 Buckets* (AWS), *blobs* (Azure), *Cloud storage* (GCP)
- We might discover these resources if they are in the DNS entries, alternatively we could use google Dorks `inurl:` and `intext:`.
	- `intext: mycompany inurl: amazonaws.com`
	- `intext: mycompany inurl: blob.core.windows.net`
- We can also find addresses in web page source code too
- [domain.glass](https://domain.glass/) can show us a lot about a company's infrastructure like this.
- [GrayHatWarfare](https://buckets.grayhatwarfare.com/) is useful after we have found some links as this will search to find the resources stored.
- We also want to check for abbreviations of the company name, a lot of IT uses the abbreviations instead.

### Company Staff
- Examining employees and their online presences can reveal lots of information (use business networks like [LinkedIn](https://www.linkedin.com/) or [Xing](https://www.xing.de/))
- Look at job posts as they could show their infrastructure stack
- Look for what skills the company is employing and what it is working with
- Search github for the employees.