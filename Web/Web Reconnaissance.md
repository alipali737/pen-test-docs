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
