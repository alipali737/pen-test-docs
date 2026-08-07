```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Open-source cloud security tool for AWS (also supports Azure/GCP/K8s) that runs hundreds of checks mapped to CIS Benchmarks, AWS Foundational Security Best Practices, GDPR, HIPAA, PCI-DSS, and more. Good first-pass automated coverage for an [[AWS Testing|AWS config review]] - use it to get broad coverage quickly, then manually verify anything high-severity before reporting.

## Installation
```bash
pipx install prowler
# or
docker run -ti --rm -v ~/.aws:/root/.aws:ro toniblyx/prowler:latest
```

## Documentation
**Cheatsheet:**
**Website:** https://github.com/prowler-cloud/prowler

## Usage
```bash
# Run against the currently configured profile, all checks
prowler aws --profile client-review

# Restrict to a specific compliance framework
prowler aws --profile client-review --compliance cis_2.0_aws

# Restrict to specific regions/services
prowler aws --profile client-review --region eu-west-1 us-east-1 --service iam s3 ec2

# Output formats for client-facing evidence
prowler aws --profile client-review -M html csv json-asff
```
- Findings are `PASS`/`FAIL`/`MANUAL` per check - filter to `FAIL` first, but skim `MANUAL` too as those often need eyes-on judgement (eg. "review policy X for intent")
- Cross-check high/critical findings manually before including in the report - automated tools produce false positives on nuanced resource policies and cross-account trust that's actually intentional
