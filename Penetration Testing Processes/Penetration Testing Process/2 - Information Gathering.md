```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

![[information-gathering.png]]

This stage is all about discovering targets and potential footholds. Information can come from many place but can be divided into the following categories:
- Open-Source Intelligence
- Infrastructure Enumeration
- Service Enumeration
- Host Enumeration

## Infrastructure Enumeration
Utilise OSINT to understand their infrastructure setup, services like DNS can be utilised to *discover name servers, mail servers, cloud instances*, and more. We can *create a map of servers and hosts* to develop more of an understanding of the target infrastructure.

Make a *list of hosts & IP addresses* and *compare them to the scope* to see if they are included. 

Its also important to try to determine the company's security measures, the more detailed the information is, the easier it will be to evade detection. *Identifying firewalls* can give us excellent understanding of what techniques could trigger an alarm.

## Service Enumeration
Find out *what services are running*, their *versions*, *what information they provide*, and the *reason it can be used*. Once we know *why a service is being used*, it gives us a clearer picture of what the overall system intention is.

It is important to also understand *if any of these versions are out of date* and could be susceptible to known vulnerabilities.

## Host Enumeration
Once we have gathered an extensive list of the infrastructure, we need to examine each host individually listed in the scoping document. We want to identify the *operating system*, *services*, and *service versions* etc.

- What role does this host/server play?
- What network components does it communicate with?
- Which services and ports does it communicate through?

**Internal Enumeration**
- Look for sensitive files, local services, scripts, applications, and information that could aid *Post-Exploitation*.

**Host discovery**
```
nmap -sL [ip range]
```

## Pillaging
This is done as part of the *Post-exploitation* stage, and is focused on collecting information that can project us further in the network. This could be names, data, credentials etc.