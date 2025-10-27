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

## 2 - Broken Object Level Authorisation ([API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) [API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/))
### 2.1 Object Access Control Manipulation
- Modify the object reference or identifier to test unauthorised access (eg. `user_id`, `order_id`)
- Check if users can modify other users' data (eg. `profile`, `cart`)
- Test for non-sequential object IDs (`UUID`, random string) to see if predictable IDs allow unauthorised access

### 2.2 Parameter Manipulation Attacks
- Burp Intruder / ParamMiner to discover hidden parameters
- Modify parameters to access unauthorised objects (eg. `/profile?user=11` -> `/profile?user=12`)
- Identify request headers that contain user-specific data and manipulate it
- Check if API properly enforces server-side verification instead of relying on client-provided identifiers

### 2.3 Mass Assignment and Over-permissive API
> Excessive Data Exposure & Mass assignment (user can change/add/delete sensitive object properties)
- Identify if API exposes object properties that should be restricted
	- `is_admin` in request
	- Look for hidden or omitted fields in responses
- Send unexpected object fields in API requests to check for mass assignment vulnerabilities
	- Try to inject fields from related objects
	- Try to inject fields that are system-controlled such as `timestamp`, `id`, and `role`
- Modify, assign, active/deactivate authorisation-related fields
- Test for object deletion / modification by modifying HTTP methods (`PATCH` and `DELETE`)

### 2.4 Insecure Direct Object Reference (IDOR)
- Try incrementing/decrementing sequential IDs
- Check previously valid IDs to check for deleted or expired object still accessible
- Modify references to access resources of other users

## 3 - Broken Function Level Authorisation ([API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/))
### 3.1 Role Escalation and Privilege Abuse
- Attempt to call privileged API endpoints as a regular user
	- eg. `/admin/deleteUser`
- Check if a user can modify their own role/permission via the API

### 3.2 Unauthorised Access to Admin API Management Functions
- Test if regular user can perform admin-level actions
	- eg. view logs, delete/create user accounts
- Identify endpoints with hidden administrative functions
- Check if admin endpoints require separate authentication beyond regular user tokens

### 3.3 Testing Different HTTP methods for PrivEsc
 - Test if unauthenticated access is given when using other HTTP methods (*Burp Intruder*)
	 - With auth token
	 - Without auth token
- Empty body / omit required fields to ensure API validation checks

### 3.4 Horizontal and Vertical PrivEsc
- Can a regular user access another user's actions (*horizontal esc*)
- Can a regular user access admin actions (*vertical esc*)
- Session hijacking or token replay to impersonate privileged user?

## 4 - Bypass Techniques ([API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) [API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/))
- Try to access API without authentication token
- Use expired token
- Modify JWT and re-sign if using weak keys
- Duplicate parameters to bypass authorisation logic
- Check API error messages for hints about authorisation failures (eg. `Access Denied` vs `Invalid User ID`)

## 5 - API Security Misconfiguration ([API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/))
### 5.1 API Exposure and Sensitive Information Disclosure
- Check if API documentation is publicly accessible
- Look for verbose error messages that reveal internal information
- Ensure API doesn't expose sensitive headers, tokens, or env vars
- Check if directory listing is enabled on API file paths
- Validate that debugging endpoints don't expose sensitive data
	- eg. `/debug`, `/health`, `/metrics`

### 5.2 Improper Authentication and Authorisation Settings


https://github.ibm.com/X-Force-Red/API-Testing-Methodology/blob/main/API%20Testing%20methodology.md