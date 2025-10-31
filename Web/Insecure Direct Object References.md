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
Sometimes  references are encoded or hashed, if we can break/decode these we can see if they are susceptible to IDOR. There may be cases we can look through the client-side javascript to identify how the reference is being hashed/encoded and then we can create our own versions.

## Prevention & Remediation
- Object-level access control mechanism (RBAC)
- Keep access privileges on the back-end, not exposing them to the front-end user to manipulate
- Use strong and unique references (like salted hashes or UUIDs)
- Map objects to secure IDs on the back-end so the user cannot guess other object references
- Do not create object references on the front-end