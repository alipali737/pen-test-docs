## Ports
Ports are between 0-65,535.

- **Ports 0 - 1023** (aka *Well-Known Ports*): Assigned to universal TCP/IP application protocols. Most common examples: HTTPS, SSH, FTP, DNS, etc. They are registered to these protocols by a global authority.
- **Ports 1024 - 49,151** (aka *Registered Ports*): Reserved for application protocols that are not specified as universal.
- **Ports 49,152 - 65,535** (aka *Private/Dynamic Ports*): These ports may be used for any process without registering the port with the global assigning authority.

| Port(s)       | Protocol        | Purpose                                                                   |
| ------------- | --------------- | ------------------------------------------------------------------------- |
| 20/21 (TCP)   | FTP             | File sharing                                                              |
| 22 (TCP)      | SSH             | Secure remote connection                                                  |
| 23 (TCP)      | telnet          | Virtual terminal emulation for a remote host                              |
| 25 (TCP)      | SMTP            | Email transfer                                                            |
| 80 (TCP)      | HTTP            | Plain-text http                                                           |
| 88 (UDP)      | Kerberos        | Key distribution server                                                   |
| 139 (TCP)     | NetBIOS         | windows name resolution (used with 445 for file & printer sharing)        |
| 161 (TCP/UDP) | SNMP            | Simple Network Management Protocol, communication between network devices |
| 389 (TCP/UDP) | LDAP            | Directory access control                                                  |
| 443 (TCP)     | SSL/TLS (HTTPS) | Encrypted http                                                            |
| 445 (TCP)     | SMB             | Windows file sharing via Server Message Block                             |
| 3389 (TCP)    | RDP             | Remote desktop                                                            |
