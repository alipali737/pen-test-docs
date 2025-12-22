```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

![[tcp-vs-osi.png]]
## OSI Model Simply Explained
- **Layer 1**: Physical Layer - Responsible for the physical transportation of data as 0's & 1's.
- **Layer 2**: Data Link Layer - Responsible for routing packets using MAC addresses.
- **Layer 3**: Network Layer - Responsible for routing packets using IP addresses.
- **Layer 4**: Transport Layer - Handles the protocol used for transport of the packet, controls what happens if a packet does make it for example.
- **Layer 5**: Session Layer - Handles starting, closing and managing sessions. Session auth etc is established here.
- **Layer 6**: Presentation Layer - Converts the data into formats usable by the application.
- **Layer 7**: Application Layer - This is the actual application and it decides how it then displays the information.

## TCP/IP Model Simply Explained
- **Layer 1**: Network Access Layer - This layer sends and recieves the data at the local network level.
- **Layer 2**: Internet Layer - This is where IP addresses and routing occurs.
- **Layer 3**: Transport Layer - TCP & UDP Protocols occur here.
- **Layer 4**: Application Layer - This layer handles sessions, translating data, and the interaction of the content at the application level, eg. HTTP, FTP, or SMTP.

### Key Tasks of TPC/IP

| Task                 | Protocol | Description                                                                                                                                                                                |
| -------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Logical Addressing   | IP       | IP takes over the logical addressing of networks and nodes. Ensuring data packets only reach their intended destination. This is done through *network classes*, *subnetting*, and *CIDR*. |
| Routing              | IP       | As a packet reaches each node, it determines the next node to move too. This means the sender doesn't need to know the location of the packet the whole way.                               |
| Error & Control Flow | TCP      | As the sender & receiver are virtually connected, they are able to send control messages to ensure the connection is still established.                                                    |
| Application Support  | TCP      | TCP and UDP ports can be used to distinguish specific applications and their communication links.                                                                                          |
| Name Resolution      | DNS      | DNS provides name resolution, through Fully Qualified Domain Names (FQDN), in IP addresses.                                                                                                |
### TCP vs UDP
- **TCP** is a *connection-oriented* protocol, a much more rigorus acknowledgement between a sender and a receiver happens before any data is sent. This protocol includes flow control and error recovery, and should be used when important or large amounts of data is needed to be sent with timing being less of a concern.
- **UDP** is a much more *lightweight* protocol that doesn't require a fixed channel between the parties. It is often for less important data that just needs to be sent quickly.

### TCP Handshake
1. Client --SYN--> Server
2. Client <--SYN-ACK-- Server
3. Client --ACK--> Server