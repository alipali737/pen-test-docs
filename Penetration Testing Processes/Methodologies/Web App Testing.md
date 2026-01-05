```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## 0 - Recon & Analysis
### 0.1 - Identify Functionality
- What functions can the application do?
- How do these functions work?

### 0.2 - Identify Data Entry Points
- Where can a user submit data?
- What types of data can be submitted?
- How is it transported? (HTTP or WS)

### 0.3 - Identify Technologies
- What technologies are in use?
- What is the rough system architecture?
	- How is the front-end served?
	- Is it public cloud?
	- Is there a separate DB?
	- Is there a WAF present?

### 0.4 - Map Application
- Manual navigation
- Burp Crawling

### 0.5 - JavaScript Analysis
- Retire.js CVEs
- Look for custom JS files that aren't common third-party
	- Endpoints
		- `XMLHttpRequest()`
		- AJAX HTTP Functions (`$.get()`, `$.post()`, `$.ajax()`)
		- React HTTP (`fetch()`)
		- `axios.get()`
	- Information Disclosures
	- Hidden Parameters
	- Any weaknesses in the code