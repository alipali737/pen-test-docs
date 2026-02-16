```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
Splunk is a log analytics tool that can analyse and visualise data. It wasn't originally designed as an SIEM tool, but if often used for security monitoring and business analytics.

These deployments often house sensitive data and are high value targets for attackers.

- Default port of 8000, Management port 8089
- Old version have default creds of `admin:changeme`
- The enterprise trial converts to a free version after 60 days which has no authentication

## Attacking
The [splunk_shell](https://github.com/0xjpuff/reverse_shell_splunk) repo offers a way to get a reverse shell via splunk's functionality.