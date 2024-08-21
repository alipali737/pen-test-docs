```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

![[penetration-testing-process.png]]

## Cleanup
Once testing is complete, we should perform any necessary cleanup, this is deleting tools/scripts uploaded, reverting any (minor) configuration changes etc. We should be detailing all of our actions so cleanup should be fairly straightforward.

If we cannot regain access to a system that needs a cleanup, we must explicitly alert the client. We should still document all our cleanup just incase the client gets alerts and needs to explain they were part of the testing.

## [[Documentation & Reporting]]
This is where we complete the deliverable report making sure we include all of our findings and important information.

## Report Review Meeting
This is when we have delivered the draft report to the client and we work through any amendments that they have. This might be with more technical experts included so we can walk through the problems.

## Deliverable Acceptance
Following the `DRAFT` report, discussions and amendments, we should deliver the `FINAL` report, marking the test as delivered. Many audit firms will not accept `DRAFT` reports so having one marked as `FINAL` is important.

## Post-Remediation Testing
Many tests include re-tests after fixes have been made. This will consist of retesting the findings and making sure they have been remediated. We will then issue a *post-remediation report* that clearly outlines the state before and after remediations.

Ideally we should show evidence that the vulnerability no longer exists.

During remediation, we are a *trusted advisor*, we must remain independent and not *fix* the problem ourselves. We may say "sanitise user input", but not re-write their code. This avoids conflict-of-interest and assessment integrity compromise.

## Data Retention
After a test concludes, we will gave a large amount of data about the client. We must work to the Scope of Work, Rules of Engagement and business processes for data retention and deletion.

## Close Out
Once delivered, accepted, and the client has been assisted where needed, we can finally close the project. We wipe or destroy any systems we used to connect to them, securely store any data we need to or delete it. This is where the invoicing etc happens too.

A post-assessment survey is always handy here. This is a really important time to self-reflect and improve our own skills and services.