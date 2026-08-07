```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Multi-cloud security auditing tool (AWS/Azure/GCP) that produces an interactive HTML report grouping findings by service with a rule-based severity rating. Good complement to [[Prowler]] in an [[AWS Testing|AWS config review]] - the HTML report is often the better artifact to hand to a client or attach to the report appendix, since it's easy to click through service-by-service.

## Installation
```bash
pipx install scoutsuite
```

## Documentation
**Cheatsheet:**
**Website:** https://github.com/nccgroup/ScoutSuite

## Usage
```bash
# Run using a named AWS CLI profile
scout aws --profile client-review

# Run using an assumed role
scout aws --profile client-review --assume-role-arn arn:aws:iam::<account-id>:role/<review-role>

# Restrict to specific regions
scout aws --profile client-review --regions eu-west-1 us-east-1
```
- Output lands in `scoutsuite-report/` - open `scoutsuite-results/scoutsuite_results_aws-<account>.js`-backed `report.html` in a browser
- Report includes a per-finding "Rationale" and "Remediation" section that's useful to lift directly (with editing) into client report writeups
- Like Prowler, treat findings as a starting point - verify severity/exploitability manually, especially around resource policies and IAM trust
