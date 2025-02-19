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

3. Select an attack type, the attack type primarily dictates how many payload pointers are used and which pointers get which payloads:
	- *Sniper attack (n=positions\*payloads)*  : Inserts each payload into each position one at a time, using a single payload set
	- *Battering ram attack (n=payloads)* : Places the same payload into each position
	- *Pitchfork attack (n=smallest_payload_set)* : Maps a payload set to each position (eg. position 1 gets from payload set 1, position 2 gets from payload set 2)
	- *Cluster bomb attack (n=product_of_all_payload_sets* : Like pitchfork, but it iterates through one payload set at a time (eg. position 1 gets first element from payload set 1, position 2 iterates through all payloads in set 2) - this lets you test every combination of payloads
4. Under the `Payloads` tab, we need to configure the 4 options: `Sets`, `Options`, `Processing`, and `Encoding`
	- **Payload Sets**
		- Select the set number
		- Select the set type
			- *Simple List* : wordlist that intruder will iterate through
			- *Runtime file* : Similar to *Simple List* but loads 1 by 1 to avoid high memory usage
			- *Character Substitution* : List of characters and their replacements
	- **Payload Options**
		- Add / Load the actual payloads into the set
	- **Payload Processing**
		- Allows us to determine fuzzing rules over the loaded wordlist (eg. skip if matches, add a suffix)
	- **Payload Encoding**
		- Specify what characters to URL encode
5. Customise the attack options in the `Options` tab, this is stuff like number of retries, pausing etc. This is also where we can specify the success conditions using a `Grep - Match` for example.

### Crawling & Scanning (Burp Scanner)
Burp scanner is a *crawler* and *scanner* (supporting both passive and active scanning). It is a *pro only feature* though. A webcrawler simply navigates to each link it finds in each page and maps a website out.
To start a new scan, we have the following options:
- Scan from a specific request from Proxy History
- Scan a new set of targets (in the Target tab)
- Scan in-scope items
> It is also useful to exclude some items that could end our session (eg. logout endpoints)
> You can also trigger a scan from the `Dashboard` tab

There are two types of scans:
- *Crawl and Audit* : This crawls and then runs the scanner against it's results
- *Crawl* : This just crawls
> A Crawl scan only follows and maps links, it does not perform fuzzing like [[#Fuzzing (Burp Intruder)]].

For authenticated crawling, we can either set credentials that Burp will use in login pages, or record a manual login in the pre-configured browser so Burp can repeat it when needed.

We can view the progress of a crawl scan in the `Dashboard>Tasks` tab. The results are then available in `Target>Site map`.

#### Passive Scanner
A passive scan performs a vulnerability scan without sending any network packets to the webserver. It analyses the source of the webpages found in the crawl earlier looking for things like DOM-based XSS vulnerabilities. Burp provides a confidence level for each vulnerability if thinks its found but is unable to make any requests to test and verify in the passive mode.

We can see the issues in the `Dashboard>Issue activity` section. We want to consider all issues identified but primarily focus on *High* severity and *Certain* confidence.

#### Active Scanner
The most powerful part of Burp Scanner, it performs a far more comprehensive scan than the passive scan by:
1. Crawling and fuzzing to identify all possible pages
2. Running a passive scan on every page
3. Sends requests to identify and verify any issues found in the Passive Scan
4. Performs JS analysis to identify further potential vulnerabilities
5. Fuzzes identified insertion points and parameters to look for common web vulnerabilities (XSS, Command Injection, SQLi etc)

> The `Logger` tab will show us all requests the go through, or are produced by burp.

Once the scan is finished we can generate a **report**:
1. Go to `Target>Site map`
2. Right click the target address and select `Issue>Report issues for this host`

### Extensions
Extensions can be installed to extend Burp's capabilities. These are community made extensions, some are for Pro version only as they extend pro features. Additionally many have dependencies that need to be installed manually prior to installing the extensions. Some extensions to research more into:

| .NET beautifier              | J2EEScan                  | Software Vulnerability Scanner |
| ---------------------------- | ------------------------- | ------------------------------ |
| Software Version Reporter    | Active Scan++             | Additional Scanner Checks      |
| AWS Security Checks          | Backslash Powered Scanner | Wsdler                         |
| Java Deserialization Scanner | C02                       | Cloud Storage Tester           |
| CMS Scanner                  | Error Message Checks      | Detect Dynamic JS              |
| Headers Analyzer             | HTML5 Auditor             | PHP Object Injection Check     |
| JavaScript Security          | Retire.JS                 | CSP Auditor                    |
| Random IP Address Header     | Autorize                  | CSRF Scanner                   |
| JS Link Finder               |                           |                                |
#### Favourite Extensions List
