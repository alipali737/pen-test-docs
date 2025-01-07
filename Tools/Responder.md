```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Responder is an LLMNR, NBT-NS, and MDNS poisoner tool with build in rogue authentication server deployment. The auth servers can be used to steal NTLM & LM hashes, HTTP basic auth etc

Supports dual IPv6/IPv4 stack.

- *SMB* Auth server supports *NTLMv1*, and *NTLMv2* hashes with Extended Security NTLMSSP. Supports SMBv2 by default.
- *MSSQL* Auth server supports *NTLMv1*, *LMv2* hashes.
- *HTTP(S)* Auth servers supports *NTLMv1*, *NTLMv2* hashes and *Basic Authentication*. HTTPS comes with a dummy set of keys but can generate new PKI pairs.
- *LDAP* Auth server supports *NTLMSSP* and *Simple Auth* (Plaintext authentication)
- *DCE-RPC* Auth server supports *NTLMSSP* hashes
- *FTP* Auth server supports clear text credentials
- *POP3* Auth server supports clear text credentials
- *IMAP* Auth server supports clear text credentials
- *SMTP* Auth server supports clear text credentials
- *DNS* Server will answer `SRV` and `A` queries (useful for ARP spoofing)
## Installation
```

```

## Documentation
**Cheatsheet:** 
**Website:** 
## Usage
