```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
*Search Engine Discovery* is when a search engine is used to discover information about a target by using specific queries to index particular information.

Specific example of Google Dorking can be found in the [Google Hacking Database](https://www.exploit-db.com/google-hacking-database).
## Common Operators
These may differ on exact syntax from one engine to another but in general :

|Operator|Operator Description|Example|Example Description|
|:--|:--|:--|:--|
|`site:`|Limits results to a specific website or domain.|`site:example.com`|Find all publicly accessible pages on example.com.|
|`inurl:`|Finds pages with a specific term in the URL.|`inurl:login`|Search for login pages on any website.|
|`filetype:`|Searches for files of a particular type.|`filetype:pdf`|Find downloadable PDF documents.|
|`intitle:`|Finds pages with a specific term in the title.|`intitle:"confidential report"`|Look for documents titled "confidential report" or similar variations.|
|`intext:` or `inbody:`|Searches for a term within the body text of pages.|`intext:"password reset"`|Identify webpages containing the term “password reset”.|
|`cache:`|Displays the cached version of a webpage (if available).|`cache:example.com`|View the cached version of example.com to see its previous content.|
|`link:`|Finds pages that link to a specific webpage.|`link:example.com`|Identify websites linking to example.com.|
|`related:`|Finds websites related to a specific webpage.|`related:example.com`|Discover websites similar to example.com.|
|`info:`|Provides a summary of information about a webpage.|`info:example.com`|Get basic details about example.com, such as its title and description.|
|`define:`|Provides definitions of a word or phrase.|`define:phishing`|Get a definition of "phishing" from various sources.|
|`numrange:`|Searches for numbers within a specific range.|`site:example.com numrange:1000-2000`|Find pages on example.com containing numbers between 1000 and 2000.|
|`allintext:`|Finds pages containing all specified words in the body text.|`allintext:admin password reset`|Search for pages containing both "admin" and "password reset" in the body text.|
|`allinurl:`|Finds pages containing all specified words in the URL.|`allinurl:admin panel`|Look for pages with "admin" and "panel" in the URL.|
|`allintitle:`|Finds pages containing all specified words in the title.|`allintitle:confidential report 2023`|Search for pages with "confidential," "report," and "2023" in the title.|
|`AND`|Narrows results by requiring all terms to be present.|`site:example.com AND (inurl:admin OR inurl:login)`|Find admin or login pages specifically on example.com.|
|`OR`|Broadens results by including pages with any of the terms.|`"linux" OR "ubuntu" OR "debian"`|Search for webpages mentioning Linux, Ubuntu, or Debian.|
|`NOT`|Excludes results containing the specified term.|`site:bank.com NOT inurl:login`|Find pages on bank.com excluding login pages.|
|`*` (wildcard)|Represents any character or word.|`site:socialnetwork.com filetype:pdf user* manual`|Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com.|
|`..` (range search)|Finds results within a specified numerical range.|`site:ecommerce.com "price" 100..500`|Look for products priced between 100 and 500 on an e-commerce website.|
|`" "` (quotation marks)|Searches for exact phrases.|`"information security policy"`|Find documents mentioning the exact phrase "information security policy".|
|`-` (minus sign)|Excludes terms from the search results.|`site:news.com -inurl:sports`|Search for news articles on news.com excluding sports-related content.|