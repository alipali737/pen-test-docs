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

[FTP Return Codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes)

**Standard Port:** 
- 21/tcp - control channel
- 20/tcp - data channel

**Version Names:** 

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## Potential Capabilities
- 

## Enumeration Checklist

| Goal | Command(s) | Refs |
| ---- | ---------- | ---- |
|      |            |      |
