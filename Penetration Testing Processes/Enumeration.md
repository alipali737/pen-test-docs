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

1. **Internet Presence**
2. **Gateway**
3. **Accessible Services**
4. **Processes**
