```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Exchange Related Group Membership
A default installation of Microsoft Exchange can open many attack vectors.
The `Exchange Windows Permissions` group isn't a protected group but can write a DACL to the domain object. This could be leveraged for a [[Abusing ACLs#DCSync|DCSync]] attack.
> Some useful details are in this [GitHub repo](https://github.com/gdedrouas/Exchange-AD-Privesc)

The Exchange group `Organization Management` is also a very powerful group, effectively the domain admins of exchange. They can also access all users' mailboxes. The users have full control of the OU called `Microsoft Exchange Security Groups`, which controls the `Exchange Windows Permissions`.

Dumping credentials from an Exchange server can also be very lucrative for cleartext passwords or NTLM hashes. This is often due to users logging in via the Outlook Web Access (OWA) and the server caching their credentials in memory.

## PrivExchange
This is also an attack that targets exchange servers, focusing on the `PushSubscription` feature. Allowing any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.

The exchange service runs as SYSTEM and is over-privileged by default (*has WriteDacl on the domain pre-2019 Cumulative Update*). We can use this to relay to LDAP and dump the [[Windows#NTDS|NTDS]] database, or we can relay and authenticate to other hosts within the domain.

## PrinterBug
We can connect to the spool's named pipe with the `RpcOpenPrinter` method, and use `RpcRemoteFindFirstPrinterChangeNotificationEx` method, forcing the server to authenticate to any host provided over SMB. The service runs as SYSTEM and can be leveraged to grant the necessary privileges for a [[Abusing ACLs#DCSync|DCSync]] attack. [this](http://web.archive.org/web/20200919080216/https://github.com/cube0x0/Security-Assessment) tool can be used with the `Get-SpoolStatus` module.

