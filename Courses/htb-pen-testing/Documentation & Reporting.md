```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## The Snapshot
An overview should be included talking about:
- what type of work was performed
- who performed it
- what IP addresses were used in the testing
- any special considerations (eg. was it performed over a VPN or within the network)
- period it was performed
- any changes to in-scope systems and resultant vulnerabilities would not be captured in the report

## Directory Format
My personal notes directory format should include:
- *Evidence* : contains all information about what happened, what was found, any notes
	- *Findings* : Vulnerabilities found and write-ups
	- *Logging output* :
	- *Misc files* : any misc files that were involved in the test
	- *Notes* : personal notes throughout the test
		1. *Administrative Information* : Useful admin information (contacts, unique objectives/flags, RoE, **To-Do list**)
		2. *Scoping information* : Any scoping information that is important (eg. IPs, URLs, any provided credentials for apps, VPNs, AD etc)
		3. *Activity Log* : high-level tracking of everything you did during an assessment for event correlation
		4. *Payload Log* : tracking the payloads being used (inc a file hash for anything uploaded and its location)
	- *OSINT* : any OSINT information gathered (links, content, descriptions etc)
	- *Scans* : scan logs & results
	- *Wireless* :
- *Deliverables* : anything that is going to the client
- *Admin* : any administration documents regarding the test