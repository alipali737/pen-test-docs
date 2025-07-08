```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
A common way to extract credentials for user accounts in AD environments is through Man-in-the-Middle attacks via *Link-Local Multicast Name Resolution* (*LLMNR*) and *NetBIOS Name Service* (*NBT-NS*) broadcasts. This technique could provide password hashes (offline crackable) or cleartext credentials. The hashes can also be used for [[Password Attacks#Pass-the-Hash|PtH]] attacks  or [[SMB & RPC|SMB]] relay attacks.

![[LLMNR#Summary]]

As LLMNR/NBT-NS is asking the local network, ANY host can respond (*including our malicious one*). [[Responder]] can be used to perform this poisoning by replying to these requests and then on, hosts will send their requests to our rogue system. This allows responder to also capture any authentication [[AD Authentication#NTHash (NTLM)|NetNTLM]] hash (which we can offline brute). We can also use the hash as is against different hosts or services (eg. LDAP). 
> [[Inveigh]] (Windows) and [[Metasploit]] can also both be used for these poisoning attacks in the case Responder isn't/can't be used

LLMNR/NBT-NS spoofing, combined with a lack of SMB signing can often lead to administrative access on hosts within the domain.

## Example Steps
1. Host A attempts to connect to a print server @`\\print01.inlanefreight.local` but accidentally typos the address
2. The DNS server states it doesn't know the host
3. Host A, then uses LLMNR to broadcast to all hosts if anyone knows the location of their typo'd address
4. [[Responder]] says that it is that address
5. Host A believes this response and sends the username and NTLMv2 hash to responder

![[Responder#Default poisoning]]

## Remediation
