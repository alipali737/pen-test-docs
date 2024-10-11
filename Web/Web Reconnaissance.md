```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
![[information-gathering.png]]
*Web Reconnaissance* is a key part of the information gathering phase of the penetration testing process. Primary goals:
- *Identify Assets* : Publicly accessible components (pages, subdomains, IPs, technologies etc)
- *Discovering Hidden Information* : Sensitive information that might be inadvertently exposed (backups, configurations, internal documents etc) - potential entry points & insights
- *Analysing the Attack Surface* : Identify potential vulnerabilities & weaknesses (assess technologies, configurations, and possible entry points)
- *Gathering Intelligence* : Information that could be used for further exploitation or social engineering (key personnel, emails, patterns of behaviour etc).

## Active Reconnaissance
These techniques **directly interact with the target system**:

| Technique                | Description                                                                                 | Example                                                                                                                       | Tools                                           | Risk of Detection                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| *Port Scanning*          | Identify open ports and the services running on them.                                       | Using `Nmap` to scan a target's open ports.                                                                                   | Nmap, Masscan, Unicornscan                      | **HIGH**: Direct interaction that can trigger an IDS and firewalls.                                                    |
| *Vulnerability Scanning* | Probe the target for known vulnerabilities, eg. outdated software, config issues.           | Running `Nessus` against a web app to find common flaws.                                                                      | Nessus, OpenVAS, Nikto                          | **HIGH**: Vulnerability scanners send exploit payloads that security solutions detect.                                 |
| *Network Mapping*        | Mapping the target's network topology, including connected devices and their relationships. | Using `traceroute` to determine the path packets take to reach a target, revealing potential network hops and infrastructure. | Traceroute, Nmap                                | **MEDIUM to HIGH**: Excessive or unusual network traffic can raise suspicion.                                          |
| *Banner Grabbing*        | Retrieving information from banners displayed by services running on the target.            | Connecting to a web server and examining the HTTP banner to identify the web server technology and versions.                  | Netcat, curl                                    | **LOW**: Banner grabbing typically involves minimal interaction but can still be logged.                               |
| *OS Fingerprinting*      | Identifying the operating system on the target.                                             | Using `Nmap`'s OS detection (`-O`) to identify the OS of the target.                                                          | Nmap, Xprobe2                                   | **LOW**: OS fingerprinting is usually passive, but more advanced techniques can be detected.                           |
| *Service Enumeration*    | Determine the specific versions of services running on open ports.                          | Using `Nmap`'s service detection (`-sV`) to determine what software version a service is using.                               | Nmap                                            | **LOW**: Service enumeration can be logged but less likely to trigger alerts.                                          |
| *Web Spidering*          | Crawling the target website to identify pages, directories, and files.                      | Running a web crawler to map out the structure of a website and discover hidden resources.                                    | Burp Suite Spider, OWASP ZAP Spider, <br>Scrapy | **LOW to MEDIUM**: Can be detected if the crawler's behaviour is not carefully configured to mimic legitimate traffic. |
## Passive Reconnaissance
These techniques gather information **without directly interacting** with the target, these techniques are very unlikely to be detected:

| Technique               | Description                                                                                               | Example                                                                                                                             | Tools                                          |
| ----------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| *Search Engine Queries* | Using search engines to uncover information about the target (websites, social media, news etc)           | Search for `[target name] employees` to find employees of the target that could reveal information.                                 | Google, DuckDuckGo, Bing, Shodan               |
| *WHOIS Lookups*         | Querying the *WHOIS* database to retrieve domain registration details.                                    | Performing a WHOIS lookup on a target domain to find the registrant's name, contact information, and name servers.                  | whois CLI, online WHOIS lookup services        |
| *DNS*                   | Analysing DNS records to identify subdomains, mail servers, and other infrastructure.                     | Using *dig* to enumerate subdomains of a target domain.                                                                             | dig, nslookup, host, dnsenum, fierce, dnsrecon |
| *Web Archive Analysis*  | Examining historical snapshots of the target to identify changes, vulnerabilities, or hidden information. | Using the Wayback Machine to view past versions of a target website to see how it has changed over time.                            | Wayback Machine                                |
| *Social Media Analysis* | Gathering information from social media platforms like LinkedIn, Twitter, or Facebook.                    | Searching LinkedIn for employees of the target to learn about roles, responsibilities, and potential social engineering targets.    | LinkedIn, Twitter, Facebook, OSINT tools       |
| *Code Repositories*     | Analysing public code repositories for exposed credentials or vulnerabilities.                            | Searching github for code snippets or repos related to the target that might contain sensitive information or code vulnerabilities. | Github, GitLab                                 |
## Fingerprinting Web Services
- *Banner Grabbing* : Analysing the returned banner of a service to reveal version information about the software.
- *Analysing HTTP Headers* : HTTP headers can contain a variety of hints towards the server software, configurations and potential weaknesses.
- *Probing for Specific Responses* : Sending specially curated requests in order to trigger certain responses (eg. errors, behaviours) could reveal weaknesses or configurations.
- *Analysing Page Content* : The content or source of a page can give information away about the technologies and configurations it uses.
### Tools

| Tool        | Description                                                                     | Features                                                                       |
| ----------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Wappalyzer  | Browser extension and online service for website technology profiling           | Identifies a range of web technologies (CMSs, frameworks, analytic tools, etc) |
| BuiltWith   | Web technology profile that provides detailed reports on a website's tech stack | Offers both free and paid plans with varying levels of detail                  |
| WhatWeb     | CLI for web fingerprinting                                                      | Uses a database of signatures to identify various web technolgies              |
| [[Nmap]]    | Network scanner that includes service fingerprinting                            | Can use NSE for specialised fingerprinting                                     |
| Netcraft    | Range of web security services, including fingerprinting and security reporting | Details on website's technology, hosting provider, and security posture        |
| [[Wafw00f]] | CLI for identifying *Web Application Firewalls* (*WAF*s)                        | Help determine if a WAF is present and if so, its type and configuration       |
## Automating Web Reconnaissance
Although relying on tooling can sometime be a pitfall and lead to false positives, it does provide some key advantages:
- *Efficiency* : significantly faster and better for repetitive tasks
- *Scalability* : can be scaled across a large domain or number of targets
- *Consistency* : ensures consistency and reliability, minimising the risk of human error
- *Comprehensive Coverage* : ensures comprehensive coverage (eg. DNS, subdomain discovery, crawling, port scanning) and minimises the potential for some vectors to be missed.
- *Integration* : many tools integrate with one another and can present their results through various platforms and standards.

Some key frameworks that exist for this purpose:
- [[FinalRecon]] : a python-based tool that offers a variety of modules (incl. SSL cert verification, Whois, header analysis, and crawling).
- [Recon-ng](https://github.com/lanmaster53/recon-ng) : another python-based modular tool, performing actions like DNS enum, subdomain discovery, port scanning, and even exploit automation.
- [theHarvester](https://github.com/laramies/theHarvester) : a python cli designed specifically for gathering emails, subdomains, hosts, employee names, open ports and banners from public sources (eg. search engines, PGP key stores, SHODAN db).
- [SpiderFoot](https://github.com/smicallef/spiderfoot) : an open-source intelligence automation tool which collects a range of information (similar to *theHarvester*) about a particular target.
- [OSINT Framework](https://osintframework.com/) : a collection of tools and resources for open-source intelligence gathering. It utilises a wide range of sources such as social media, search engines, and public records.