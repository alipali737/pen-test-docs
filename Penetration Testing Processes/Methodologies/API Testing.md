```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## 0 - SSLScan & Vulnerability Scan
```bash
sslscan [host]
```
> Check for yellow things as these are potential problems

1. Check for TLS 1.0 / 1.1 as these are insecure
2. Check for insecure ciphers being used (*eg. SHA1 hashing is considered insecure now*)

```bash
nuclei -l targets.txt -H [header] -p socks5://127.0.0.1:9999
```

## 1 - Broken Authentication ([API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/))
- Identify API endpoints that handle objects, resources, or sensitive data
	- eg. `/users/[user_id]` & `/orders/[order_id]`
- Determine authentication methods
	- Bearer token (JWT)
	- API Keys
	- OAuth 2.0/OpenID Connect
	- Session tokens
	- SAML token
	- mTLS
	- Basic Auth
- Identify roles and privileges that define access
	- eg. `admin`, `user`, `guest`

## 2 - Broken Object Level Authorisation ([API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/))
### 2.1 Object Access Control Manipulation
- Modify the object reference or identifier to test unauthorised access (eg. `user_id`, `order_id`)
- Check if users can modify other users' data (eg. `profile`, `cart`)
- Test for non-sequential object IDs (`UUID`, random string) to see if predictable IDs allow unauthorised access

### 2.2 Parameter Manipulation Attacks
- Burp Intruder / ParamMiner to discover hidden parameters
- Modify parameters to access unauthorised objects (eg. `/profile?user=11` -> `/profile?user=12`)
- Identify request headers that contain user-specific data and manipulate it
- Check if API properly enforces server-side verification instead of relying on client-provided identifiers

### 2.3 Mass Assignment and Over-permissived API



https://github.ibm.com/X-Force-Red/API-Testing-Methodology/blob/main/API%20Testing%20methodology.md