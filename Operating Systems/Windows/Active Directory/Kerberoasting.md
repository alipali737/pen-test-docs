```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
Kerberoasting is a lateral movement/privilege escalation technique used in AD environments. It attacks [[Active Directory#Service Principal Name (SPN)|Service Principle Name (SPN)]] accounts.
![[Active Directory#Service Principal Name (SPN)]]
Domain accounts are often used to run services to overcome network auth limitations of local built-in accounts. However, any domain user can request a Kerberos ticket for any service account in the same domain (*This is also possible across trusts if the relationship permits it*). Once you have an account (credentials, NTLM hash, shell in context, or SYSTEM access on a domain joined host), you can perform a Kerberoasting attack.

Domain accounts that run services are often local administrators or high privileged domain accounts due to the distributed nature of how the services interact in the network.

**The Key Vulnerability**
Even with a Kerberos ticket for one of these privileged accounts, we cannot just execute commands as that user. However, the ticket ([[Kerberos#Ticket Granting Service (TGS)|TGS-REP]]) is *encrypted with the service account's NTLM hash*. This then means that theoretically, the plain-text password for the service account could be brute forced (eg. [[Hashcat]]).

Often, the password for these service accounts are weak or reused, so breaking one could give you access to a variety of accounts or servers. Cracking one of these service accounts, could give you an attack path through a service to gain RCE.

The attack can be performed from multiple places:
- From a non-domain joined Linux host using valid domain user credentials
- From a domain-joined Linux host as root after retrieving the `keytab` file
- From a domain-joined Windows host authenticated as a domain user
- From a domain-joined Windows host with a shell in the context of a domain account
- As `SYSTEM` on a domain-joined Windows host
- From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)) `/netonly`

### Kerberoasting with GetUserSPNs.py
`GetUserSPNs.py` is an [impacket toolkit](https://github.com/SecureAuthCorp/impacket) script for working with SPNs.
#### Request TGS tickets for SPN accounts
```bash
# Requests from all accounts
GetUserSPNs.py -dc-ip [ip] [domain]/[user] -request -outputfile all_accounts_tgs

# Requests from a single account
GetUserSPNs.py -dc-ip [ip] [domain]/[user] -request-user [target-user]
```
> The output will be in format for [[Hashcat]] - mode: 13100
> We can then use a tool like [[CrackMapExec]] to validate the account credentials once cracked.



