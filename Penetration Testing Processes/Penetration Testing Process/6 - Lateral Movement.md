```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

![[lateral-movement.png]]

Once we have gained access to the system ([[4 - Exploitation]]), gathered local data and escalated our privileges ([[5 - Post-Exploitation]]), we can now move laterally. The goal here is to *test what an attacker can do within the entire network*. The overall goal for a PT is to exploit a public system, and get sensitive data or find all the ways the network could be made unstable (Ransomeware for example).

We can move to this stage from either [[4 - Exploitation]] or [[5 - Post-Exploitation]] depending on if we are unable to escalate our privileges directly.
## Pivoting
This is a process that allows us to use the exploited host as a proxy, meaning we can use all our tools on our attack machine. We basically use the exploited host as a route for all our network requests.

By using a host in the internal network, we can now reach (and deeper test) networks that aren't publicly reachable. This means we can scan them and penetrate deeper, this is called *Pivoting* or *Tunneling*.

The goal of pivoting is to access inaccessible systems via an intermediary system.

> [[Pivoting, Tunnelling, and Port Forwarding]]
## Evasive Testing
We need to be considerate of the evasive expectations, we might need to bypass things like *network segmentation*, *threat monitoring*, *IPS/IDS*, *EDR*, etc.

## Information Gathering
We want to get an overview of the network, including how many systems can be reached from our system. We may already have this information from config or settings we found in [[5 - Post-Exploitation]].

## Vulnerability Assessment
This is where *groups* and *rights* play an important role in what we can do. We might be able to intercept shares etc.

## (Privilege) Exploitation
This is where we are attempting to exploit more systems, using our higher privileges where possible. We might be able to intercept password hashes and steal more accounts. Often the data we find can be used for multiple things.

## Post-Exploitation
We must go through the post-exploitation steps on each system we compromise. We must also be aware (often in the contract) of how we should handle any sensitive data that we find.

Finally, we are ready for the *proof-of-concept* for our clients.
