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
- Verify all API endpoints that need authentication, enforce it
- Ensure CORS policies are properly restrictive
	- Send request with foreign `Origin` header (`Origin: https://xfr-test.com`)
	- `Access-Control-Allow-Origin` present? value = `*`? echoed origin? specific domain?
		- Make sure request's origin is not reflected 
	- `Access-Control-Allow-Credentials` present and true?
	- `Access-Control-Expose-Headers`
		- Check if any headers containing credentials are leaked
	- `Access-Control-Allow-Methods` & `Access-Control-Allow-Headers` for preflight requests?
- Check for weak authentication mechanisms
	- Guessable API keys
	- No MFA
- Test JWT configurations
	- Token properly signed and validated?
	- Test JWT with weak algorithms (`none` algorithm)
	- Downgrade attack (eg. RS256 -> HS256), set Algo to HS256 and sign using the server's public key (pub key could be at `.well-known/jwks.json`)
	- If symmetric key, try dictionary attacks for weak secret key
	- Kid (Key ID) header injection : path traversal, database injection, key confusion, alternative key
		- Could point it to `/dev/null` and then sign the key with an empty string
	- Test short-lived tokens and proper revocation mechanisms
	- Ensure Keys, JWTs, and session tokens aren't hardcoded in source or logs
	- Server-side denied list or a revocation mechanism?

## 6 - Rate Limiting / Throttling ([API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) [API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/))
### 6.1 Reconnaissance
- Response headers for rate limiting
	- `X-RateLimit-Limit`
	- `X-RateLimit-Remaining`
	- `Retry-After`
	- `429 Too Many Requests` responses
- Identify sensitive or abuse-prone functionalities
	- Authentication flow
	- OTP/email/SMS - MFA
	- Self-registration
	- Search endpoints
	- Password reset
### 6.2 Bypass Techniques
- Header Manipulation
	- `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`
	- Rotate IP headers while sending requests
	- Change `User-Agent`, `Origin`, or `Referer`
- Authentication Tokens
	- Check if limits are per-user/token
	- Use same token but from different IPs
	- Use multiple accounts to test global vs per-user throttling
- IP Rotation
	- Send requests from different IPs -> test per-IP enforcement
	- Use `tor`, `residential proxy` or `cloud IPs` to rotate origins
- Parameter Variation
	- Slightly change request body/query parameters within each request
	- Add random data to avoid match detection
- Path Manipulation
	- Trailing slashes (`/api/resource` vs `/api/resource/`)
	- Use encoded path `/api%2Fresource`
- Multi-threaded/Concurrent Requests
	- 10, 50, 100 threads and observe
		- Consistent behaviour
		- Server performance impact

## 7 - Server-Side Request Forgery
### 7.1 Identify potential SSRF endpoints
- Look for endpoints that request remote files
	- File downloaders / image fetchers
	- PDF/image thumbnail generation
	- URL preview, metadata extraction
	- Webhooks, callbacks, pingbacks
	- Import/Parsers
	- URL validators, scanners
	- S3 or storage integrations (`url`, `file_path`)
	- SSRF sinks embedded in JSON, YAML, or XML payloads

### 7.2 SSRF Payload Tests
- Test URLs to confirm if server makes a request
	- Public URLs (eg. `Burp Collaborator`)
	- Internal URLs (eg. `http://127.0.0.1`, `http://[::1]`)

### 7.3 Bypass Techniques for SSRF Filtering
- IP Obfuscation
	- Decimal: `http://21307060433` -> `127.0.0.1`
	- Hex: `http://0x7f000001`
	- Octal: `http://0177.0000.0000.0001`
- Double URL encoding:
	- `http://%25%33%31%32%37.0.0.1`
- Redirect chains
	- `http://attacker.com/redirect?url=http://127.0.0.1`
- DNS rebinding payloads (host name resolves to external IP first, then internal)

### 7.4 Cloud Metadata Access
> Specific IP allows Cloud VM to access its own metadata info without an internet connection
- AWS
	- `http://169.254.169.254/latest/meta-data/`
	- `http://169.254.169.254/latest/user-data`
- GCP
	- `http://metadata.google.internal/computeMetadata/v1/instance/`
- Azure
	- `http://169.254.169.254/metadata/instance?api-version=2021-01-01`

### 7.5 Internal Services
- Internal IP ranges
	- `127.0.0.1`
	- `192.168.x.x`
	- `10.x.x.x`
	- `172.16.x.x`
- [[Common Ports]]: `80`, `443`, `8080`, `8443`, `3000`, `5000`, `2375`, `22`, `3306`
- DNS
	- `api.internal`
	- `kube-dns.kube-system.svc.cluster.local`



https://github.ibm.com/X-Force-Red/API-Testing-Methodology/blob/main/API%20Testing%20methodology.md