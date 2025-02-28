```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
Kerberos is a stateless open standard authentication system often found in windows systems (often used in [[Active Directory]] environments). It is a ticket-based system, meaning that each service that requires authentication isn't given an account password but given a ticket exclusively for that service. Kerberos keeps all the tickets on the local system. This system prevents tickets from being used for another purpose as they are service specific.

As part of [[Active Directory]] Domain Services (AD DS), Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets. When a client initiates a login request to a system:
1. The client requests a ticket from the KDC (AS-REQ), they encrypt this request using the user's password (*symmetric encryption*)
2. If the KDC (*who holds the user's password too*) can decrypt the request using their password, it will create a [[#Ticket Granting Ticket (TGT)]], sending it back to the user.
3. The user then presents its TGT to a Domain Controller to request a [[#Ticket Granting Service (TGS)]] ticket, encrypting with the associated service's NTLM password hash.
4. Finally the client requests access to the required service by presenting the TGS to the application or service, which decrypts it with its password hash.

Kerberos essentially decouples a user's credentials from their requests to consumable resources, ensuring their password isn't sent over the network. The KDC doesn't store previous transactions, so the whole system instead relies on valid TGT's for TGS' to work. Having a valid TGT, assumes the requester has already proven their identity... This could be taken advantage of it we *steal a ticket*.

## Ticket Granting Ticket (TGT)
The TGT is the first ticket obtained on a Kerberos system. The TGT permits the client to obtain additional Kerberos tickets or TGS.
When a user requests a TGT, they must authenticate to the domain controller by encrypting the current timestamp with their password hash. Once the domain controller validates the user's identity (the domain knows their password hash, meaning they can decrypt the timestamp), it sends a TGT for all future requests. Once a user has their ticket, they no longer need to prove who they are with a password.

## Ticket  Granting Service (TGS)
The TGS is requested by users who want to use a service. These tickets allow services to verify the user's identity. 

**Example:** If a user wants to connect to a database, it will request a TGS from the Key Distribution Centre (KDC), presenting their TGT. Once validated, a TGS will be given to the database server for authentication.

## Installing the Kerberos client on Linux
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