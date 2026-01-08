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

## 5 - Data Validation
### 5.1 - SQL Injection
- [[SQLMap]]
- [[SQL Injection Cheatsheet]]

### 5.2 - XXS
- [[Cross-Site Scripting (XSS)]]

### 5.3 - OS Command Injection
- [[OS Injection]]
- `|| ping -c 10 127.0.0.1 ; x || ping -n 10 127.0.0.1 &` - should cause a 10 second delay

### 5.4 - Path Traversal
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
- `../../../../../../../../../../etc/passwd` & `..\..\..\..\..\..\..\..\..\..\etc\passwd`

### 5.5 - Script Injection
- Specific to whatever scripting language is injectable
- `javascript:alert(window.origin)` `;echo 1111` `response.write 1111`

### 5.6 - File Inclusion
- [[File Inclusion]]

### 5.7 - SMTP Injection
- Anything where a user's email is taken could be vulnerable
- `<email>%0aCc:<email>` `<email>%0d%0aCc:<email>` `<email>%0aBcc:<email>` 
- `<email>%0d%0aBcc:<email>` `%0aDATA%0afoo%0a%2e%0aMAIL+FROM:+<email>%0aRCPT+TO:+<email>`

### 5.8 - Native Code Flaws
- Buffer Overflows
	- Use Burp Intruder's `Character Blocks` payloads to test for overflow in a string
	- Example buffer sizes that are generally suitable to test : `1100`, `4200`, `33000`
	- Look for anomalies in the behaviour (eg. errors, malformed responses, abruptly closed TCP connection, no response, unexpected data returned)
- Integer Vulnerabilities
	- Look for integer-based data, particularly length indicators, which may be used to trigger integer vulnerabilities
	- Try sending values representing the boundary cases for the signed and unsigned versions of different size integers
		- `0x7f and 0x80 (127 and 128)` `0xff and 0x100 (255 and 256)` `0x7ffff and 0x80000 (32767 and 32768)` `0xffff and 0x10000 (65535 and 65536)` `0x7fffffff and 0x80000000 (2147483647 and 2147483648)` `0xffffffff and 0x0 (4294967295 and 0)`
- String Format Vulnerabilities
	- Submitting long format specifiers (*remember to url encode `%` as `%25`*)
	- `%n%n%n%n%n%n%n%n%n%n%n` `%s%s%s%s%s%s%s%s%s%s%s%s` 
	- `%1n!%2n!%3n!%4n!%5n!%6n!%7n!%8n!%9n! etc...` `%1s!%2s!%3s!%4s!%5s!%6s!%7s!%8s!%9s! etc...`

### 5.9 - SOAP Injection
- Submit rogue closing tag : `</foo>` to check for errors happening if its being inserted into a SOAP message
- If an error: `<foo></foo>` and the error should go away
- If item is returned in response, try: `test</foo>` or `test<foo></foo>` then the item is being inserted into an XML-based message

### 5.10 - LDAP Injection
- Submit an LDAP wildcard `*` and see if anything is returned
- Try an increasing number of closing brackets `))))))))`
- `)(cn=*` `*))(|(cn=*` `*))%00`
- Could try adding additional attributes (comma seperated)
	- `cn` `c` `mail` `givenname` `o` `ou` `dc` `l` `uid` `objectclass` `postaladdress` `dn` `sn`

### 5.11 - XPath Injection
- Check for different behaviour from: `' or count(parent::*[position()=1])=0 or 'a'='b` or `' or count(parent::*[position()=1])>0 or 'a'='b`
- If param is numeric: `1 or count(parent::*[position()=1])=0` or `1 or count(parent::*[position()=1])>0`
- If any of these cause different behaviour without causing an error, we can likely extract arbitrary data 1 byte at a time.
- Use a series of conditions with the following form to determine the name of the current node's parent: `substring(name(parent::*[position()=1]),1,1)='a'`
	- Once the name has been extracted, we can extract all data within the XML tree: `substring(//parentnodename[position()=1]/child::node()[parent()=1]/text(),1,1)='a'`

### 5.12 - Back-end Request Injection
- If there is anywhere an internal server name or IP address is specified in a parameter
	- We can use an arbitrary server and port, monitoring for a timeout
	- Try with localhost
	- Try with our IP and watch for connections

### 5.13 - XXE Injection
- [[XML External Entity Injection]]

## 6 - Identity Management
### 6.1 - Identify Roles 