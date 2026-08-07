```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
AWS exploitation framework (Rhino Security Labs) built around modules for recon, enumeration, privilege escalation, persistence, and exfiltration. Only relevant to an [[AWS Testing|AWS config review]] if **active exploitation** of identified misconfigurations (eg. proving an IAM privesc chain actually works, pivoting from a compromised EC2 role) is in scope - for a pure read-only config review, stick to [[Prowler]]/[[ScoutSuite]]/[[PMapper]].

## Installation
```bash
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu && sh install.sh
```

## Documentation
**Cheatsheet:**
**Website:** https://github.com/RhinoSecurityLabs/pacu

## Usage
```bash
python3 pacu.py

# Inside the Pacu shell
Pacu > import_keys client-review   # import an existing AWS CLI profile
Pacu > set_regions eu-west-1 us-east-1
Pacu > run iam__enum_permissions
Pacu > run iam__privesc_scan       # checks current session against known privesc paths
Pacu > run ec2__enum
Pacu > run s3__bucket_finder
```
- `iam__privesc_scan` is the most directly useful module for a config review - confirms which of the known IAM privesc techniques the current principal can actually perform, rather than just theorising from the policy JSON
- Get explicit written authorisation before running exploitation modules (persistence, lateral movement) - most config review SOWs won't cover this by default
