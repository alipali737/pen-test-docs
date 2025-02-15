```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
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

