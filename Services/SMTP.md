```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Simple Mail Transfer Protocol* (*SMTP*) is a protocol for sending emails on an IP network.

**Standard Port:** 
- *25*/tcp : Most used for connections between SMTP servers, often blocked because of spammers nowadays.
- *465*/tcp : Originally designed for SMTP with SSL, but SSL was replaced by TLS so this port is only in legacy systems.
- *587*/tcp : Default port for email submission, SMTP over TLS.
- *2525*/tcp : Not officially associated but some email services offer this port if others are blocked

**Version Names:** 

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
1. A TCP connection is established with the SMTP server from the SMTP client
2. The client sends the email data (subject, addresses, content etc)
3. The server runs a program called a *Mail Transfer Agent* (*MTA*), which performs DNS on the recipient's domain if it it different from the senders.
4. The client completes data transmission and the server closes the connection
5. The server then repeats the whole process acting as the client this time to transfer the email to another SMTP server until it reaches its final destination.
### Commands
- `HELO/EHLO` : Start of SMTP connection, `EHLO` is for a specialised type of SMTP
- `MAIL FROM` : Describes the sender `MAIL FROM:<user@example.com>`
- `RCPT TO` : Describes the recipient `RCPT TO:<user@example.com>` (this can be sent multiple times)
- `DATA` : Contains the actual email data that will be visible to the user (date, addresses, subject, recipient, content etc)
- `RSET` : Reset the connection without closing it (used if incorrect data is sent)
- `QUIT` : Closes the connection

### SMTP Server Programs
- *Mail Submission Agent* (*MSA*) : Receives emails from the SMTP client (A.K.A *Relay* server). Validates email (origin etc).
- *Mail Transfer Agent* (*MTA*) : Finds the next server in the delivery chain, may use `MX` DNS records. Checks email for size & spam.
- *Mail Delivery Agent* (*MDA*) : Receives emails from MTAs and stores them in the recipient's email inbox

| Client | Submission Agent | Open Relay | Mail Delivery Agent | Mailbox   |
| ------ | ---------------- | ---------- | ------------------- | --------- |
| MUA    | MSA              | MTA        | MDA                 | POP3/IMAP |

## Configuration


## Potential Capabilities
- 

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
### Nmap Scripts
- 