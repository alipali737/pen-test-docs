## Ports
Ports are between 0-65,535.

- **Ports 0 - 1023** (aka *Well-Known Ports*): Assigned to universal TCP/IP application protocols. Most common examples: HTTPS, SSH, FTP, DNS, etc. They are registered to these protocols by a global authority.
- **Ports 1024 - 49,151** (aka *Registered Ports*): Reserved for application protocols that are not specified as universal.
- **Ports 49,152 - 65,535** (aka *Private/Dynamic Ports*): These ports may be used for any process without registering the port with the global assigning authority.

| Port(s)       | Protocol / Service              | Purpose                                                                   |
| ------------- | ------------------------------- | ------------------------------------------------------------------------- |
| 20/21 (TCP)   | [[FTP]]                         | File sharing                                                              |
| 22 (TCP)      | [[SSH]]                         | Secure remote connection                                                  |
| 23 (TCP)      | [[telnet]]                      | Virtual terminal emulation for a remote host                              |
| 25 (TCP)      | [[SMTP]]                        | Email transfer                                                            |
| 53 (TCP)      | [[DNS]]                         | Domain Name Server                                                        |
| 80 (TCP)      | HTTP                            | Plain-text http                                                           |
| 88 (UDP)      | [[Kerberos]]                    | Key distribution server                                                   |
| 110 (TCP)     | [[IMAP & POP3\|POP3]]           | Older protocol for the retrieval of emails                                |
| 111 (TCP)     | [[SMB#RPCclient\|RPC]]          | Remote Procedure Call                                                     |
| 135 (TCP)     | [[WMI]]                         | Windows Management Instrumentation                                        |
| 137 (TCP)     | [[SMB]]                         | Windows file sharing via Server Message Block                             |
| 139 (TCP)     | [[SMB\|NetBIOS]]                | windows name resolution (used with 445 for file & printer sharing)        |
| 143 (TCP)     | [[IMAP & POP3\|IMAP]]           | Retrieval of emails                                                       |
| 161 (TCP/UDP) | [[SNMP]]                        | Simple Network Management Protocol, communication between network devices |
| 389 (TCP/UDP) | [[LDAP]]                        | Directory access control                                                  |
| 443 (TCP)     | SSL/TLS (HTTPS)                 | Encrypted http                                                            |
| 445 (TCP)     | [[SMB\|CIFS]]                   | Common Internet File System (SMB for Unix systems)                        |
| 587 (TCP)     | [[SMTP]]                        | SMTP over TLS                                                             |
| 993 (TCP)     | [[IMAP & POP3\|IMAP]] (TLS/SSL) | IMAP over TLS                                                             |
| 995 (TCP)     | [[IMAP & POP3\|POP3]] (TLS/SSL) | POP3 over TLS                                                             |
| 1433 (TCP)    | [[MSSQL]]                       | Microsoft SQL Server                                                      |
| 2049 (TCP)    | [[NFS]]                         | Network File Share                                                        |
| 3306 (TCP)    | [[MySQL]]                       | MySQL Server                                                              |
| 3389 (TCP)    | [[RDP]]                         | Remote desktop                                                            |
| 5985 (TCP)    | [[WinRM]] (HTTP)                | Windows remote management                                                 |
| 5986 (TCP)    | [[WinRM]] (HTTPS)               | Windows remote management                                                 |
