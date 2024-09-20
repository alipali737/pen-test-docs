```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*File Transfer Protocol* (FTP) runs on the application layer of the TCP/IP stack. It is a protocol for transferring files between machines over TCP. It creates two channels, *control channel (TCP p21)* and *data channel (TCP p20)*.

The client sends commands on the control channel, the server responds with status codes.
Data is send on the data channel, and the protocol watches for errors.

If connection is broken during transmission, the transport is resumed after re-established contact.

*Active mode*: client informs server which port to send responses to.
*Passive mode*: if firewall blocks incoming connections, the server announces a port the client can establish the data channel, since the client creates the connection, the firewall doesn't block the transfer.

FTP can also potential offer *anonymous* FTP, which doesn't require the user to login with a password.

[FTP Return Codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes)

**Standard Port:** 
- 21/tcp - control channel
- 20/tcp - data channel

**Version Names:** 

| service name | releases link                            | notes                                                                                                                                                                                                                  |
| ------------ | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| vsFTPd       | https://security.appspot.com/vsftpd.html | *very secure FTP daemon*, for Unix-like systems (linux). Can be secured by SSL/TLS.<br>- Default config: */etc/vsftpd.conf*<br>- Users: */etc/ftpusers*<br>*hide_ids=YES* config setting can mask uid & gids for files |
## Potential Capabilities
- Upload payloads or malicious files / tools
- Download sensitive data
- FTP Bounce (uses `PORT` cmd to basically proxy through a server)
## Enumeration Checklist

| Goal                                       | Command(s)                                                                 | Refs                                       |
| ------------------------------------------ | -------------------------------------------------------------------------- | ------------------------------------------ |
| Footprint the service                      | nmap [IP] -n -Pn -p[PORT] -vv -sV --script "\*ftp\* and (default or safe)" | https://nmap.org/book/man-nse.html         |
| Try anonymous connection                   | ftp anonymous@[target]                                                     |                                            |
| Exploits for version                       | searchsploit [version]<br><br>google [version]                             |                                            |
| FTP Brute force                            | nmap [IP] -n -Pn -p[PORT] --script ftp-brute.nse<br><br>hydra              |                                            |
| List All                                   | LIST -R                                                                    |                                            |
| Get/Put files                              | get/mget<br>put/mput                                                       | /etc/passwd<br>/etc/sudoers<br>/etc/shadow |
| Download all files                         | wget -m --no-passive ftp://[user]:[pass]@[IP]                              |                                            |
| Search for config files for other services |                                                                            |                                            |
| Search for SSH keys                        | /home/user/.ssh/authorized_keys<br>/home/user/.ssh/id_rsa                  | Use john to crack keys?                    |
## Connecting to FTP
```shell
nc -nv [IP] [PORT]
telnet [IP] [PORT]
```
If SSL/TLS is needed, `openssl` can provide a client
```shell
openssl s_client -conect [IP]:[PORT] -starttls ftp
```
