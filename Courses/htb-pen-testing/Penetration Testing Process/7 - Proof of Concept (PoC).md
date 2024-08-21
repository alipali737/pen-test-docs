```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

![[proof-of-concept.png]]

A *PoC* is a *basis for future work*, so in our case this is the necessary steps to secure the network by confirming discovered vulnerabilities. This is where we prove vulnerabilities in the systems we test.

A *PoC* could be *documentation* of the vulnerabilities found. A more practical version could be a *script* or *code* to automatically exploit the vulnerabilities. Sometimes an admin will attempt to combat the actions of the script specifically, missing the point that this is just *one way* of exploiting the vulnerability. We want to make sure that the admins understand how to fix the root issues, not just stopping the script specifically.

The report we give will paint the full picture. It shows how multiple flaws can build a very impactful chain. Its important to fix all the flaws, not just break the chain.

We need to convey the root cause, eg. is a user has a weak password (`password123`) then, the actual problem is no *password policy*.