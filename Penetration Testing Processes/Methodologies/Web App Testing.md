```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## 0 - Recon & Analysis
### 0.1 - Identify Functionality
- What functions can the application do?
- How do these functions work?

### 0.2 - Identify Data Entry Points
- Where can a user submit data?
- What types of data can be submitted?
- How is it transported? (HTTP or WS)

### 0.3 - Identify Technologies
- What technologies are in use?
- What is the rough system architecture?
	- How is the front-end served?
	- Is it public cloud?
	- Is there a separate DB?
	- Is there a WAF present?

### 0.4 - Map Application
- Manual navigation
- Burp Crawling

### 0.5 - JavaScript Analysis
- Retire.js CVEs
- Look for custom JS files that aren't common third-party
	- Endpoints
		- `XMLHttpRequest()`
		- AJAX HTTP Functions (`$.get()`, `$.post()`, `$.ajax()`)
		- React HTTP (`fetch()`)
		- `axios.get()`
	- Information Disclosures
	- Hidden Parameters
	- Any weaknesses in the code

## 1 - Authentication
### 1.1 - Password Policy
- What is the policy?
- Incomplete validation of long passwords?

### 1.2 - Username Enumerations
- Different application responses for usernames

### 1.3 - Password Attack Prevention
- Rate limiting for logons?
- Account lockouts
- Captcha limits
- Protections against bruteforce / automation?

### 1.4 - reCAPTCHA Attacks
- Don't send the parameter related to the captcha
- Try other HTTP verbs
- Covert to and from JSON
- Send empty captcha parameter
- Check if value of captcha is in the source code
- Check if value is in the cookie
- Try and old captcha value
- Try use same value multiple times with same or different sessions
- OCR?

### 1.5 - Account Recovery
- Weak challenge?
- Password hints?
- Host Header injection in recovery email?
- Weak recovery links? (Patterns, repeatable, direct references)

### 1.6 - Remember Me
- Check for persistent cookies
- Any patterns with similar usernames?
- Any unique identifiers that could be stolen

### 1.7 - Impersonation
- Can it be manipulated for priv esc?

### 1.8 - Username Uniqueness
- If self-registration:
	- Can register username multiple times? (What about passwords if this is the case?)
	- Username enumeration might be possible

### 1.9 - Credentials Predictability
- If creds are generated automatically, are there any patterns or sequences

### 1.10 - Unsafe Transmission of Creds
- Unencrypted transfer
- Stored in cookies or local storage (XSS target)
- Transported in URL (could be cached, logged etc)

### 1.11 - Unsafe Distribution of Creds
- How are new accounts provisioned?
- Do activation URLs contain patterns? Can they be used multiple times?

### 1.12 - Insecure Storage of Credentials
- If we have access to hashes, are there repeat hashes (usually weak/common passwords)?
- Are credentials stored in browser.

### 1.13 - Fail-Open Logic
- Empty strings
- Remove name/value pair
- Submit long and short values
- Submit strings instead of numbers
- Submit numbers instead of strings
- Submit the same named parameter multiple times with the same and different values

## 2 - Session Management
### 2.1 - Session Mechanism
- How are sessions tracked? (Cookies, Tokens, Session-less, obfuscated or encrypted form sent from client)
- Request auth page removing items until session breaks, once value is found that controls the session, change the value 1 byte at a time and see if its still accepted.

### 2.2 - Token Generation
- Obtain the tokens for several accounts, ideally with similar names. Record the tokens and compare them for repeat patterns (Hex, Base64 etc)
- Generate and compare a large number of tokens and check for entropy with Burp sequencer.
	- Try to determine any encoding
	- Is there any components that are time-based, IP-based etc?
	- Try Burp Intruder's "bit flipper" to sequentially modify each bit

### 2.3 - Token Handling
- Insecure Transmission (note everywhere they are being transmitted)
	- Ensure always using encrypted transmission
	- Secure flag for cookies
	- If mixed HTTP & HTTPS is used, ensure that a new token is created in the HTTPS section otherwise its vulnerable to interception during the HTTP area
- Disclosure in logging
	- Are tokens present in logging?
- Mapping of tokens to sessions
	- Are concurrent sessions allowed?
	- Are tokens per-user?
- Session Termination
	- How long are sessions valid for?
	- Replay previous tokens after log-outs
	- Can a user clear all active logged on sessions themselves as a security measure?
- Session Fixation
	- Is a new token issued after authentication?
- CSRF
	- If application solely relies on HTTP cookie for transmission of session tokens, it may be vulnerable to CSRF
	- Identify requests that perform sensitive actions (eg. change password)
	- PoC with another user account and browser
- Cookie Scope
	- Review `Set-Cookie` headers for proper scoping and flags
	- Issues can occur if cookies are scoped to parent domain, as other apps within the domain could attack these

## 3 - Access Control
### 3.1 - Requirements
- What access control should be in place?
	- What should a regular user be able to see and do?
	- What should an admin be able to see and do?
- What type of access is in place (RBAC, DAC, MAC, Permission-based)

### 3.2 - Multiple Accounts
- Vertical privilege escalation - can we access privileged areas as a low-level user?
- Horizontal privilege segregation - can we access other users' data?
	- Enumerate / brute-force identifiers for data in other accounts and try them

### 3.3 - Insecure Methods
- Try using other HTTP methods (eg. HEAD instead of GET) to identify if any URLs are being controlled insecurely.
- Look for parameters and fields that can be manipulated.
- Perform an authorised action normally, then try to repeat it with a modified or missing Referrer header as sometimes this is used in an unsafe way.

## 4 - Configuration and Deployment
### 4.1 - HTTP methods
- Try other HTTP methods
- What information does TRACE give?

### 4.2 - HTTP Headers
- `Content-Security-Policy` defines what servers can provide content for the requested webpage. This can prevents some XSS or content-injections by preventing a compromised webpage from referencing third-party content.
- HTTP `Strict-Transport-Security` (HSTS) instructs the browser to disable future plaintext HTTP connections to the same web server. Makes MITM harder.
- `Referrer-Policy` defines when the browser should send a referer [sic] header for secondary requests. This can prevent referrer leakage to third-party websites.
- `X-Content-Type-Options` instructs the browser to disable automatic detection of the content's MIME type. Automatic detection can introduce XSS vulnerabilities.
- `X-Frame-Options` defines when the browser can open the site in an iframe. This prevents click-jacking and other misuse of content by third-party sites.

### 4.3 - Cross-Domain Policy
- Overly permissive cross-domain policies
	- Server reflects a third-party `origin` in its response
	- If `Access-Control-Allow-Credentials: true` is set (often browsers will block these insecure combos) but in theory a malicious website could take advantage of a user already being logged in to access authenticated API responses.

### 4.4 - Forced Browsing / Directory Busting
- gobuster / ffuf
- Look for sensitive pages, errors, unreferenced content, API interfaces, raw data