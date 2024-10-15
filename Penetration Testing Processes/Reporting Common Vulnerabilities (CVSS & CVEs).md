```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Common Vulnerability Scoring System (CVSS)
[Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/) is a industry standard scoring system for calculating the severity of a vulnerability. It is often used in conjunction with the so-called [Microsoft DREAD](https://en.wikipedia.org/wiki/DREAD_(risk_assessment_model)).
- **D**amage Potential
- **R**eproducibility
- **E**xploitability
- **A**ffected Users
- **D**iscoverability

CVSS scoring consists of the *exploitability* and the *impact* of an issue. The *exploitability* measurements consist of *access vector*, *access complexity*, and *authentication*. The *impact* metrics consists of the *CIA triad*.
![[CVSS metrics.png]]

### Base Metric Group
#### Exploitability Metrics
These metrics evaluate the technical means needed to exploit the issue:
- *Attack Vector* : How is the vulnerable system accessible?
	- Network - accessible over a network (remotely exploitable)
	- Adjacent - must be logically adjacent (eg. shared proximity through bluetooth, or on a logical network like a local IP subnet, or a within a secure domain like a admin network)
	- Local - the target must be accessed locally not via a network stack
	- Physical - the attacker has to have physical access to the machine
- *Attack Complexity* : Whether security-enhancing conditions have to be evaded?
	- Low - no additional target-specific evasion is needed
	- High - evasion or circumvention of security measures in place is needed
- *Attack Requirements* : Does the vulnerability rely on any specific deployment or execution conditions?
	- None - no specific conditions are required
	- Present - a specific deployment or execution condition is needed (eg. a race condition needs to be won)
- *Privileges Required* : Are any privileges requires prior to exploitation?
	- None - an unauthenticated user can perform the exploit
	- Low - basic capabilities are needed
	- High - significant (eg. admin) privileges are needed
- *User Interaction* : Is another (non attacker) user required to exploit?
	- None - no interaction is needed by a human user
	- Passive - a user involuntarily carries out an action (eg. navigating to an unknowingly compromised website)
	- Active - the user must consciously perform an action (eg. accepting prompts or security warnings, connecting a device)
#### Impact Metrics
These measure the impacts of the issue to the CIA triad.
- *Confidentiality*
- *Integrity*
- *Availability*

### Threat Metrics
These measure the current state of the exploit techniques or code availability for a vulnerability:
- *Exploit Maturity* : The current availability and likelihood of the vulnerability being attacked
	- Not Defined - unable to find maturity (assumes 'Attacked' as a worst case)
	- Attacked - reports of this vulnerability being attacked OR solutions to simplify exploit attempts are available
	- Proof-of-Concept - PoC is available but no reports of attacks
	- Unreported - no knowledge of PoC available & no reports (eg. neither of the above) 