```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## 1 - SSLScan
```bash
sslscan [host]
```
> Check for yellow things as these are potential problems

1. Check for TLS 1.0 / 1.1 as these are insecure
2. Check for insecure ciphers being used (*eg. SHA1 hashing is considered insecure now*)

## 2 - ParamMiner
1. Use Burp Extension ParamMiner to identify if there are any secret parameters that can be injected

## 3 - Nuclei Vulnerability Scan
```bash
nuclei -l targets.txt -H [header] -p socks5://127.0.0.1:9999
```


https://github.ibm.com/X-Force-Red/API-Testing-Methodology/blob/main/API%20Testing%20methodology.md