```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
"Principal Mapper" (NCC Group) - builds a graph of every IAM principal in an account and the access/privilege-escalation edges between them, then lets you query it. This is the fastest way to answer "can any low-privilege principal reach admin?" across a whole account in an [[AWS Testing|AWS config review]], instead of manually chaining IAM policies by hand (see [[AWS Testing#2.4 - Privilege Escalation Paths]]).

## Installation
```bash
pipx install principalmapper
```

## Documentation
**Cheatsheet:**
**Website:** https://github.com/nccgroup/PMapper

## Usage
```bash
# Build the graph for the currently configured profile
pmapper --profile client-review graph create

# Visualize it
pmapper --profile client-review visualize

# Query for privilege escalation paths to a specific principal
pmapper --profile client-review query "who can do iam:CreateUser"
pmapper --profile client-review query "can <principal-arn> do sts:AssumeRole with <role-arn>"

# Find all admin-equivalent principals
pmapper --profile client-review query "preset privesc"
```
- Requires broad `iam:Get*`/`iam:List*` (covered by `SecurityAudit`) to build an accurate graph - confirm the review role has this before running
- The `preset privesc` query is usually the single highest-value output for the report - it lists every principal with a viable path to administrative access, ranked by path length
