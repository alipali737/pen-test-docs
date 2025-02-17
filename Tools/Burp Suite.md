```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 4 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Burp suite is a web proxy that has a range of additional features (crawling, fuzzing etc)

## Installation
- https://portswigger.net/burp/releases/
- You also require a JRE

## Documentation
**Cheatsheet:** 
**Website:** https://portswigger.net/burp/
## Usage
### Proxy Setup
Either you can use the built in pre-configured browser or we can configure a normal browser to use *default* port `8080` as a proxy. (Extensions like [Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) can make this easier to do).

> Response interception can be toggled on in the settings in burp (proxy>options)
### Installing the CA certificate for HTTPS proxy
1. Once using the proxy, navigate to http://burp and download the CA certificate
2. Then import the certificate into the browser (eg. firefox - about:preferences#privacy>view-certificates>authorities)
3. We need to make sure to trust the CA certificate to identify email users and websites.
### Automatic Modification
In the (*Proxy>Options>Match and Replace*) we can define criteria to automatically match and modify the requests. 
> This can be useful if we want to change a header for example in every request.
> This method can also be performed on the response too by adding another rule

### Proxy with other tools

#### [[Proxychains]]
As [[Proxychains]] supports HTTP proxying, we can setup a proxy in the config: `http 127.0.0.1 8080` which will direct any network traffic produced when using proxychains through Burp.

#### [[Nmap]]
Nmap has a built in `--proxies` flag that can used to specify any HTTP proxies to use. It is recommended to skip host discovery when using this option too `-Pn`.
```bash
nmap --proxies http://127.0.0.1:8080 -Pn -p<port> -sC <server_ip>
```
> This is an experimental feature (as indicated by `man nmap`) so sometimes functions or traffic isn't routed through the proxy. Therefore [[#Proxychains]] is a more bulletproof option.

#### [[Metasploit]]
Some modules in [[Metasploit]] will also allow for `PROXIES` to be set (eg. `auxiliary/scanner/http/robots_txt`) which we can set with `HTTP:127.0.0.1:8080`.

### Fuzzing (Burp Intruder)
Burp intruder is a tool for web fuzzing and scanning. It can replace CLI web fuzzing tools like [[Gobuster]], `dirbuster`. It can be used to *fuzz pages, directories, sub-domains, parameters, parameter values, and many other things*.
> The community edition of Burp, is throttled at 1 request per second (which is extremely slow compared to CLI tools).

1. Send a request to the intruder, we should see the target details in the `target` tab
2. In the `Positions` tab, we can place the payload position pointer. Highlight the value you wish to replace with the words from the wordlist and either press `Add §` or manually add a `§` to either side:
```HTTP
GET /§DIRECTORY§/ HTTP/1.1
HOST: ...
```
> this will make a pointer called `DIRECTORY`

3. 