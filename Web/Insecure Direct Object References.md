```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
IDOR vulnerabilities are incredibly common in web applications. IDOR happens when there is direct reference to an object, eg. filename, sequential IDs. These mean that a malicious actor could reasonably guess the references to other similar objects. If there is a **lack of strong access control** this could lead to disclosures or escalation of privileges.

IDOR primarily exists due to the lack of sufficient access control on the back-end. The direct object references are just the attack vector, the issue is the access control. Access control systems are not easy to implement and are often therefore not done, leaving a major vulnerability in the system.

## Encoding & Hashing