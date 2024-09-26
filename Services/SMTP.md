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

Two key issues with the protocol:
- *No delivery confirmation*, specification for this type of notification is defined but no format is specified by default, so usually only english-lang error message and email header are returned.
- *No user authentication on connection*, allows mail spoofing with fake addresses. Techniques and protocols like [DomainKeys](http://dkim.org/) (*DKIM*), the [Sender Policy Framework](https://dmarcian.com/what-is-spf/) (*SPF*). 
> This is where *Extended SMTP* (*ESMTP*) has been developed to create a TLS connection, meaning the [AUTH PLAIN](https://www.samlogic.net/articles/smtp-commands-reference-auth.htm) extension in SMTP is now safe to use.

**Standard Port:** 
- *25*/tcp : Most used for connections between SMTP servers, often blocked because of spammers nowadays.
- *465*/tcp : Originally designed for SMTP with SSL, but SSL was replaced by TLS so this port is only in legacy systems.
- *587*/tcp : Default port for email submission, SMTP over TLS.
- *2525*/tcp : Not officially associated but some email services offer this port if others are blocked

**Version Names:** 

| service name  | releases link | notes |
| ------------- | ------------- | ----- |
| Postfix smtpd |               |       |
## How it works
1. A TCP connection is established with the SMTP server from the SMTP client
2. The client sends the email data (subject, addresses, content etc)
3. The server runs a program called a *Mail Transfer Agent* (*MTA*), which performs DNS on the recipient's domain if it it different from the senders.
4. The client completes data transmission and the server closes the connection
5. The server then repeats the whole process acting as the client this time to transfer the email to another SMTP server until it reaches its final destination.
### Commands
- `HELO/EHLO` : Start of SMTP connection, `EHLO` is for a specialised type of SMTP
- `AUTH PLAIN` : AUTH is a service extension used to authenticate the client
- `MAIL FROM` : Describes the sender `MAIL FROM:<user@example.com>`
- `RCPT TO` : Describes the recipient `RCPT TO:<user@example.com>` (this can be sent multiple times)
- `DATA` : Contains the actual email data that will be visible to the user (date, addresses, subject, recipient, content etc)
- `RSET` : Reset the connection without closing it (used if incorrect data is sent)
- `VRFY` : Check if a mailbox is available for message transfer
- `EXPN` : Check if a mailbox is available for messaging
- `NOOP` : Request a response from the server to prevent time-out
- `QUIT` : Closes the connection
- 

### SMTP Server Programs
- *Mail Submission Agent* (*MSA*) : Receives emails from the SMTP client (A.K.A *Relay* server). Validates email (origin etc).
- *Mail Transfer Agent* (*MTA*) : Finds the next server in the delivery chain, may use `MX` DNS records. Checks email for size & spam.
- *Mail Delivery Agent* (*MDA*) : Receives emails from MTAs and stores them in the recipient's email inbox

| Client | Submission Agent | Open Relay | Mail Delivery Agent |           Mailbox            |
| :----: | :--------------: | :--------: | :-----------------: | :--------------------------: |
| *MUA*  |      *MSA*       |   *MTA*    |        *MDA*        | *[[IMAP & POP3\|POP3/IMAP]]* |
| Step 1 |      Step 2      |   Step 3   |       Step 4        |            Step 5            |
> *Mail User Agent* (*MUA*) : The email client

### ESMTP
- Usually what people mean when they talk about SMTP.
- Uses TLS after the `EHLO` command by sending `STARTTLS`.
- Allows plaintext extensions to now be used safely, eg. [AUTH PLAIN](https://www.samlogic.net/articles/smtp-commands-reference-auth.htm) for user authentication.

## Configuration
```shell
cat /etc/postfix/main.cf

cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
```

As it is often unknown where the emails will come from that we trust, sometimes the `mynetworks` config setting is set to `0.0.0.0/0`. This allows the sending of fake emails.
## Potential Capabilities
- Sometimes we can check the validity of users with the `VRFY` command as it may be configured to output a `252` code if a user exists. (Not reliable so check with dummy user).
- 

## Enumeration Checklist

| Goal                                | Command(s)                  | Refs                                                            |
| ----------------------------------- | --------------------------- | --------------------------------------------------------------- |
| Nmap service scan                   | sudo nmap [ip] -sC -sV -p25 |                                                                 |
| Connect via telnet to send commands | telnet [ip] [port]          |                                                                 |
| Enumerate users                     | smtp-user-enum              | https://pentestmonkey.net/tools/user-enumeration/smtp-user-enum |

### Nmap Scripts
- smtp-commands : tries sending smtp commands (*default script*)
- smtp-open-relay : tries to identify the target as an open relay
- smtp-enum-users : enum users with `RCPT`