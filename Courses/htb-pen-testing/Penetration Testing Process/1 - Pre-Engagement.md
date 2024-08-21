```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

![[pre-engagement.png]]
## Three Components
1. Scoping questionnaire : 
2. Pre-engagement meeting : 
3. Kick-off meeting : 

## Non-Disclosure Agreements (NDAs)
- *Unilateral NDA* : only applies confidentiality to one party, the other may share with third parties
- *Bilateral NDA* : both parties must keep the resulting and acquired information confidential (most common for PTs)
- *Multilateral NDA* : a confidentiality agreement between more than two parties

It is also **critical to consider who is contracting the penetration test**, as not everyone has the authorisation to contract a test. This could include senior IT management, C-Level staff, or Auditors.

## Important Documents
| Document                                              | Purpose                                                    | Timing for Creation                                 |
| ----------------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------- |
| NDA                                                   | Protect confidentiality of the test systems and knowledge  | *After* initial contact                             |
| Scoping Questionnaire                                 | Get an idea of what the client is looking for              | *Before* the Pre-engagement meeting                 |
| Scoping Document                                      | The agreed scope for the test                              | *During* the Pre-engagement meeting                 |
| Penetration Testing Proposal (Contract/Scope of Work) | The actual contract for the test and what will be involved | *During* the Pre-engagement meeting                 |
| Rules of Engagement (RoE)                             | What rules must be followed                                | *Before* the Kick-off meeting                       |
| Contractors Agreement (Physical assessments)          | A contract to protect physical intrusion and testing       | *Before* the Kick-off meeting                       |
| Reports                                               | Deliverable reports for the client                         | *During* and *after* the conducted penetration test |
## Scoping Questionnaire
- We would typically send this questionnaire to better understand what they want
- Typically explains and asks them to choose a service they would like
- This gives us an initial idea of what they want, what it will likely include etc allowing us to align expectations and adequately deliver on their needs
- This could include things like:
	- How many hosts?
	- How many domains in scope?
	- What are the objectives for Red Teaming?
	- Do we need to bypass Network Access Control (NAC)?
- Finally we ask about information disclosure and evasiveness (if applicable)
- Based on all this information we will create the *Scoping Document*

## Pre-engagement Meeting
This is where the contract (A.K.A Scope of Work) is set out as well as the Rules of Engagement (RoE). It is important to walk through with the client exactly what they are after and make sure they are happy and write consent for the test.

## Kick-Off Meeting
This is where the client and the penetration testers have signed all the contractual documents and now go over the nature of the test and how it will take place. This is where procedures (eg. vulnerability notification) will be covered, what would stop testing activities (eg. unresponsive, discovery of illegal content or a threat actor).

Inform the client of the risks during a test (log entries and alarms, locked user accounts from brute-forcing potentially etc). Make sure the client notifies the team if it negatively impacts their network.

It explains and reassures non-technical people of the process and our expertise. We must adapt to exactly the wished of the client and not deviate.