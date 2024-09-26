```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Internet Message Access Protocol* (*IMAP*) & *Post Office Protocol* (*POP3*) are protocols for accessing emails from a mail server. 

*IMAP* allows for online management of emails directly on the server and supports folder structures. The client-server protocol allows synchronisation of local email clients with the mail server (like a network file share). This means that it does require an active connection to manage emails.

*POP3* only provides listing, retrieving, and deleting emails as functions at the email server. It downloads emails from the server onto the local client, removing them on the server (meaning they can't be accessed on another client).



**Standard Port:** 
- IMAP : 143/tcp
- IMAP : 993/tcp : alternative port sometimes used in SSL/TLS
- POP3 : 110/tcp
- POP3 : 995/tcp : SSL/TLS port

**Version Names:** 

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
1. Communication is established to the server via port *143*/tcp.
2. Text commands are sent, each has a unique identifier so responses from the server don't need to be waited for as they will be linked to each identifier when they are returned.
3. The user is authenticated with username & password to access the mailbox
4. SMTP sends emails and they are copied into an IMAP folder, accessible by all clients.

*IMAP* is unencrypted by default for all communications (incl passwords). Typically SSL/TLS are mandated by mail servers for additional security.


## Configuration
### IMAP Useful Commands
- `1 LOGIN username password`
- `1 LIST "" *` : List all directories
- `1 CREATE "INBOX"`
- `1 DELETE "INBOX"`
- `1 RENAME "ToRead" "Important"`
- `1 LSUB "" *` : Returns an array of *subscribed* or *active* mailboxes
- `1 SELECT INBOX`
- `1 UNSELECT INBOX`
- `1 FETCH <ID> all` : Get all data associated with a message in the mailbox
- `1 CLOSE` : Removes all messages with the *Deleted* flag set
- `1 LOGOUT`
### POP3 Useful Commands
- `USER username`
- `PASS password`
- `STAT` : Number of emails on the server
- `LIST` : Get number and size of all emails
- `RETR <id>` : Get an email by its ID
- `DELE <id>`
- `CAPA` : Display server capabilities
- `RSET` : Reset transmitted information
- `QUIT`

### Dangerous Config
- `auth_debug` : Enables all auth debug logging
- `auth_debug_passwords` : Passwords and the scheme gets logged
- `auth_verbose` : Logs unsuccessful auth requests
- `auth_verbose_passwords` : Passwords used for auth are logged
- `auth_anonymous_username` : Specifies the username to be used when logging in via the ANONYMOUS SASL mechanism

## Potential Capabilities
- Read all send and received emails
- View executed commands on the server
- Log in as anonymous

## Enumeration Checklist

| Goal                        | Command(s)                                                                       | Refs |
| --------------------------- | -------------------------------------------------------------------------------- | ---- |
| Scan ports and services     | sudo nmap [target] -p110,143,993,995 -sC -sV                                     |      |
| Gain connection information | curl -k 'imaps://[ip]' --user user:password -v                                   |      |
| TLS Interactions            | openssl s_client -connect [ip]:pop3s<br><br>openssl s_client -connect [ip]:imaps |      |
### Nmap Scripts
- 