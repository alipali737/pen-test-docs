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
### 2.1 - Session Tracking
- How are sessions tracked? (Cookies, Tokens, Session-less, obfuscated or encrypted form sent from client)
- Request auth page removing items until session breaks, once value is found that controls the session, change the value 1 byte at a time and see if its 
- 

### 2.2 - 