```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Kerberos is a stateless open standard authentication system often found in windows systems (often used in [[Active Directory]] environments). It is a ticket-based system, meaning that each service that requires authentication isn't given an account password but given a ticket exclusively for that service. Kerberos keeps all the tickets on the local system. This system prevents tickets from being used for another purpose as they are service specific.

**Standard Port:** 
- 88/tcp+udp


## How it works
As part of [[Active Directory]] Domain Services (AD DS), Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets. When a client initiates a login request to a system:

1. When a user logs in, they encrypt the timestamp of the request using their password. The request is then sent to the KDC to verify the authentication by decrypting it.
2. The KDCchecks the authentication service request (AS-REQ), verifies the user information, then issues a [[#Ticket Granting Ticket (TGT)]], encrypting it with the secret key of the krbtgt account.
3. The user then sends the TGT to (the/a) DC, requesting a [[#Ticket Granting Service (TGS)]] for a specific service (TGS-REQ).
4. The TGS is encrypted with the NTLM password hash of the service or computer account in whose context the service instance is running, and then delivered back to the user (TGS-REP).
5. The user finally then presents the TGS to the service, which decrypts it using its NTLM hash, and allows the user to connect to the resource (AP-REQ).
![[Pasted image 20250228154536.png|700]]

Kerberos essentially decouples a user's credentials from their requests to consumable resources, ensuring their password isn't sent over the network. The KDC doesn't store previous transactions, so the whole system instead relies on valid TGT's for TGS' to work. Having a valid TGT, assumes the requester has already proven their identity... This could be taken advantage of it we *steal a ticket*.

### Ticket Granting Ticket (TGT)
The TGT is the first ticket obtained on a Kerberos system. The TGT permits the client to obtain additional Kerberos tickets or TGS.
When a user requests a TGT, they must authenticate to the domain controller by encrypting the current timestamp with their password hash. Once the domain controller validates the user's identity (the domain knows their password hash, meaning they can decrypt the timestamp), it sends a TGT for all future requests. Once a user has their ticket, they no longer need to prove who they are with a password.

### Ticket  Granting Service (TGS)
The TGS is requested by users who want to use a service. These tickets allow services to verify the user's identity. 

**Example:** If a user wants to connect to a database, it will request a TGS from the Key Distribution Centre (KDC), presenting their TGT. Once validated, a TGS will be given to the database server for authentication.

## Configuration
### Installing the Kerberos client on Linux
```bash
# Install the package
$ sudo apt-get install krb5-user -y

# View the config
$ cat /etc/krb5.conf

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

<SNIP>
```
Once setup we can use a tool like [[Evil-Winrm]] with Kerberos authentication.

## Potential Capabilities
- PassTheTicket attacks
- Stealing user credentials / accounts
- Identifying Domain Controllers (as they will have this port exposed)

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
### Nmap Scripts
- 