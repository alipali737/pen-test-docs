---
layout: page
title: OWASP Web Security Testing Guide
parent: Methodologies
grand_parent: Testing
---
# {{ page.title }}
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---
https://owasp.org/www-project-web-security-testing-guide/

The OWASP Web Security Testing Guide is a project to help people understand the *what, why, when, where,* and *how* of testing web applications.

The project presents a complete testing framework that describe both the general testing framework and the techniques required to implement the framework in practice.

# Summarised Overview
## [Information Gathering](#1-information-gathering)
{: .no_toc }
Gathering information about the target, its architecture, tech stack, surrounding systems, entrypoints, and execution paths.
- [**Search engine discovery**](#search-engine-discovery-reconnaissance)
  - Use search engines to identify information about the target - *Google, Bing, Baidu, Wayback*
- [**Web Application Enumeration**](#web-application-enumeration)
  - Discover applications & services running on the target IP - *Manual, Nmap, nslookup, Netcraft*
- [**Map Application Architecture**](#map-application-architecture)
  - Map the system architecture (firewalls, proxies, servers, applications) - *Manual, Burp, Network Requests, Ncat, Nmap*
- [**Web Server Fingerprinting**](#web-server-fingerprinting)
  - Identify type & version of web server software - *Ncat, Nmap, Nikto, Netcraft*
- [**Fingerprint Web Application Framework**](#fingerprint-web-application-framework)
  - Identify the web application framework(s) being used & any detailed information about them - *Manual, WhatWeb, Wappalyzer*
- [**Review Webpage Content**](#review-webpage-content-for-information-leakage)
  - Gain intelligence from webpage files (HTML Source, JS, Source Map files) - *Manual (DevTools)*
- [**Map Execution Paths**](#map-execution-paths-through-the-application)
  - Identify execution paths and workflows through application (Path, Data flow, Race) - *ZAP, Spiders*
- [**Identify Application Entry Points**](#identify-application-entry-points)
  - Identify entry points into the application (eg. GETs & POSTs); Understand parameters in requests; Analyse responses for cookies, unexpected status codes, abnormal headers - *Burp, ZAP, OWASP ASD*

---

# Principles of Testing
[Section Link](https://arc.net/l/quote/iqeedvsr)
- **There is no silver bullet** : there is no one method to solve the problem of insecure software. Security is a process and not a product, taking lots of different approaches to ensuring security (scanners, protections, tests etc).
- **Think Strategically, not Tactically** : Just simply patching a vulnerability without proper root cause analysis with hinder the security of an application. Time and care should be taken to address the root cause of the insecurity and fix it at the source.
- **SDLC is King** : Security should be incorporated into the SDLC to ensure security is embedded through the entire development process.
- **Test Early and Test Often** : The earlier a bug is found, the easier, faster, and cheaper it is to fix.
- **Test Automation** : Test automation should be incorporated into the development pipeline to establish a baseline security analysis.
- **Understand the Scope of Security** : It is critical to understand how much security a project will require. Assets should be given a classification that states how they are to be handled (eg. confidential, secret, top secret). Additional security may be needed for personal data for instance.
- **Thinking outside the box** : Normal cases will test the application being used as it is expected. The job of a good security test is to test the unexpected. Tests should focus on thinking like an attacker trying to break the application. This will also highlight any incorrect assumptions made by developers.
- **Understand the Subject** : Understanding the technical documentation of a system is key to identifying weaknesses (use cases, data-flow, architecture etc).
- **Use the Right Tools** : Understanding what security tooling does exactly, and what it cannot do.
- **The Detail is Key** : False positives happen and can undermine the report's valid message. A test should take care to test every possible section of application logic and use case scenario for possible vulnerabilities.
- **Use Source Code when Available** : Black-box tests are useful for demonstrating how vulnerabilities can be exposed in a production system, however without visibility of the source code, some vulnerable paths may never be tested.
- **Develop Metrics** : Understanding the metrics for an applications security can reveal security trends within an organisation.
- **Document the Test Results** : A report should be suitable for all parties that may have concerns in the results (eg. stakeholders). It should highlight risks to the business owner, pin-pointing the fault for developers to address, as well as instructions for another tester to reproduce. Using a template is essential for a security tester to ensure the right information is provided without the report writing becoming burdensome.

---

# Web Application Testing

Throughout a test, it is important to gather all the destinations, URLs, access points, and understood knowledge of the system as the test is conducted.

## [1. Information Gathering](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/)
### Search Engine Discovery Reconnaissance
The purpose of this process is to utilise search engines to discover information leakage regarding a target. This could come directly from the target or in-directly from forums, blogs, social media etc.

**Test Objective:** Identify sensitive design and configuration information about the target directly or in-directly exposed.

**Test Intentions:** Aim is to discover sensitive information about the target eg.
- Network diagrams and configurations
- Archived content from key users (admins, employees)
- Authentication implementations or procedures and username formats
- Usernames, passwords, and private keys
- Error message content
- Non-production versions of the target

**Search Engines:**
- [Google](https://www.google.com/) : Most popular search engine globally
- [Bing](https://www.bing.com/) : Microsoft search engine
- [Baidu](https://www.baidu.com/) : China’s most popular search engine
- [Wayback Machine](https://archive.org/web/) : Internet archives
- [DuckDuckGo](https://duckduckgo.com/) : Privacy-focused search engine compiling many different sources

**Search Operators**
This syntax can be used to craft specific results from searches (also known as Dorking or Google Hacking) generally following the `<operator>:<query>` format. Some of the most useful are:
- `site:` will limit the search to the provided domain.
- `inurl:` will only return results that include the keyword in the URL.
- `intitle:` will only return results that have the keyword in the page title.
- `intext:` or `inbody:` will only search for the keyword in the body of pages.
- `filetype:` will match only a specific filetype, i.e. png, or php.
- `cached:` will show you previously indexed content (useful to see content that may have changed)

Databases such as [Google Hacking Database](https://www.exploit-db.com/google-hacking-database), or [Google Hacking Diggity Project](https://resources.bishopfox.com/resources/tools/google-hacking-diggity/) (for sites Bing or Shodan) are available.

**Remediation:**
- Review the confidentiality and sensitivity of information relating to the target system before its posted online
- Periodically review the sensitivity of existing information online

---

### Web Server Fingerprinting
This process is to identify the type and version of web server that a target is running on using key indicators and recognisable traits. Many tools do this automatically now but the underlying process is useful to know.

**Test Objectives:** To identify the type and version of a running web server to further discover known vulnerabilities

**Banner Grabbing**
Often in HTTP responses from a web server, information about the system is sent in the header. This can give away server type and version information to an attacker. Tools like [Telnet](https://en.wikipedia.org/wiki/telnet), [Nmap](https://nmap.org/), and [NetCat](https://nmap.org/ncat/) can all do this. Tools like `openssl` can also do this for SSL connections.

Sometimes, servers may remove this information from the response header, however the server type could still be inferred by checking the order in which the information appears.

In an Apache response the data order is:
- Date
- Server
- Content-Type

but for an nginx site it is:
- Server
- Date
- Content-Type

This method is not for definite but can give indications.

**Malformed Requests**
Sending incorrect or malformed requests to a server could prompt it to return a default error response. This can give away the server type by analysing the returned result if it hasn't be customised.

**Automatic Scanning Tools**
These tools use large databases and more specific server probes to quickly identify information about a web server or service on a network. Some common tools are:
- [Netcraft](https://toolbar.netcraft.com/site_report) : an online tool for scanning websites
- [Nikto](https://github.com/sullo/nikto) : an open-source CLI tool
- [Nmap](https://nmap.org/) : an open-source CLI tool which also has a GUI version, [Zenmap](https://nmap.org/zenmap/)

**Remediation**
- Obscure web server information in headers
- Using a hardened reverse proxy server to add an additional layer of security between the web server and the internet
- Updating web server default messages
- Ensuring servers are kept up-to-date with patches

---

### Web Application Enumeration
Often a single IP address will host multiple web servers or services that should be enumerated for discovery. However, like with all enumeration, **it is critical to stay within scope**.

**The Three Factors**
There are three key factors that influence the number of applications for a given DNS name (or IP address):
- **Different Base URL** : A website could break norms and actually begin the address after the `/` following the base domain eg. `example.com/website1` & `example.com/website2`. These aren't 'secret' but just not explicitly advertised and could be differing applications.
  - **Approaches:**
    - If a web server is misconfigured and allows directory browsing it may be possible to identify these applications
    - Using search operators for the site may reveal URLs that could point to non-obvious applications that have been cached
    - Probing or using directory enumeration tools could identify common addresses
    - Vulnerability scanners can often help in approaching this

- **Non-standard Ports** : Web apps usually live on port 80 (http) or 443 (https), there is nothing stopping them being on non-standard ports. The same applies for other protocols.
  - **Approaches:**
    - Utilising a port scanner such as `nmap` can identify http[s] services running on arbitrary ports.
    - A full scan of the whole 64k TCP port address space is required to test all ports
    - Using something like `nmap -Pn -sT -sV -p0-65535 <IP Address>` (`-Pn` : treats all as online; `-sT` : attempt TCP Connect; `-sV` : probe to determine service info) would be sufficient to examine the output and identify any services that are HTTP or look like SSL (should be probed to confirm https using the browser, not all SSL services are HTTPS, some are just SSL-wrapped services).

- **Virtual Hosts** : An IP can be associated to one or more symbolic names via DNS. This means that aside from `example.com` a `webmail.example.com` or `helpdesk.example.com` could exist and utilise the `HOST` header to indicate the target application.
  - **Approaches:**
    - DNS Zone Transfers can potentially be used (although this is a bit out-dated now) to get all associated aliases for an IP address in a DNS (tools: `nslookup`,`host`,`dig`)
      - First look up the name servers for an address `host -t ns <target url>`
      - Then you can request a DNS zone transfer which will list any aliases `host -l <target url> <name server>`
    - DNS inverse queries are similar to a ZT but queries an IP address for any associated symbolic-names, relying on a PTR (Pointer Record) - `dig -x <ip address>
    - There are websites such as [Netcraft search DNS](https://searchdns.netcraft.com/?host) service that will perform this lookup itself
    - Reverse-IP services are like inverse queries but query a web-app instead of a name server. It is good to use multiple to collate results: [Domain Tools Reverse IP](https://www.domaintools.com/reverse-ip/), [Bing](https://bing.com/) syntax: `ip:x.x.x.x`, [Webhosting info](http://whois.webhosting.info/) syntax: `http://whois.webhosting.info/x.x.x.x`

---

### Review Webpage Content for Information Leakage
It is important to review the webpage content and source files to better understand the application and potentially gain valuable information for profiling the target (could also be useful for social engineering).

**Test Objectives:**
- Review HTML source for `META`data and comments leaking information
- Review JS files to understand application client logic
- Review source map files

Source map files will usually be loaded when the DevTools are open. Testers can find the source map files by adding `.map` to the extension of a JS file.
For example: `/static/js/main.chunk.js` becomes `/static/js/main.chunk.js.map` which reveals:
```
{
  "version": 3,
  "file": "static/js/main.chunk.js",
  "sources": [
    "/home/sysadmin/cashsystem/src/actions/index.js",
    "/home/sysadmin/cashsystem/src/actions/reportAction.js",
    "/home/sysadmin/cashsystem/src/actions/cashoutAction.js",
    "/home/sysadmin/cashsystem/src/actions/userAction.js",
    "..."
  ],
  "..."
}
```

---

### Identify Application Entry Points
Understanding how the application uses HTTP requests & responses can show valuable entry points that can be tested later. Particular attention should be paid to `GET` & `POST` operations.

**Test Objectives:** Identify possible entry and injection points through request and response analysis

**Requests:**
- Identify where GETs and POSTs are used
- Identify all parameters in POST requests
- Identify hidden parameters in POST requests
- Identify all query params in GET requests
- Understand the purpose of each param found (and whether is encoded / encrypted) as it may or may not be required later
- Identify any abnormal additional or custom type headers (eg. `debug: false`)

**Responses:**
- Identify is cookies are set, modified, or added to (`Set-Cookie` header)
- Identify any redirects (3xx HTTP codes), 4xx codes (particularly 403 Forbidden), and 5xx server errors during normal responses (eg. unmodified requests).
- Note any interesting headers eg. `Server: BIG-IP` means that the server is load balanced so test to see if one server is incorrectly configured

**OWASP Attack Surface Detector**
A tool (plugin for ZAP & Burp) that can be used to automatically identify endpoints in an application's source code, being exported as JSON. This could be given by a customer who doesn't want to provide the source itself too. [CLI Available Here](https://github.com/secdec/attack-surface-detector-cli/releases), [Burp ASD Plugin](https://github.com/secdec/attack-surface-detector-burp/wiki).

---

### Map Execution Paths Through the Application
Building out a large map / spreadsheet to map out the application and its execution paths can help a tester understand the workflows and potential areas to explore.

**Test Objective:** Map the target application's execution paths and understand its principal workflows

**Types of Approaches:**
- **Path** : Follow each path, inputting random, boundary, invalid data for testing each decision path. Thoroughness but grows exponentially.
- **Data Flow** : Tests how data (inputted by a user) flows through the application (transformation and usage). Understand what goes in, how its manipulated, used, and stored.
- **Race** : Test multiple concurrent instances of the application manipulating the same data.

**Spidering:** You can use something like the spider tool in the [Zed Attack Proxy (ZAP)](https://github.com/zaproxy/zaproxy) to analyse and discover new URLs on a target.

---

### Fingerprint Web Application Framework
Similar to understanding the web server being used, it is also possible to use similar pointers to identify which web application framework is being used.

**Test Objective:** Fingerprint the components being used by the web application

**Common Pointer Locations:**
- HTTP Headers
- Cookies
- HTML Source Code
- Specific files and folders
- File extensions
- Error messages

**HTTP Headers**
The `X-Powered-By` header can be a dead giveaway on any HTTP response. Carefully checking the headers and understanding what each of them mean is a key identifier for an application's framework.

**Cookies**
Many frameworks have their own specific cookies and these can narrow down the attack surface.

**HTML Source Code**
Explore the source code for giveaways of the framework: comments, framework specific paths, and script variables can all be used as fingerprints of a framework.

**Specific files and folders**
Using forced browsing and something like burp intruder, it is possible to determine the existence of specific files and folders as each framework has its own directory structure. There is a value in setting up a temporary installation of the frameworks and web apps being tested to gain a better understanding of what infrastructure or functionality. The [FuzzDB wordlists of predictable files/folders](https://github.com/fuzzdb-project/fuzzdb) is a good list for this exact test.

Always check the `Robots.txt` file first as this may give away information on this.

**File Extensions**
Understanding file extensions can give away key identifiers eg. `.php`.

**Error Messages**
Error messages can also give away frameworks through file names or default messages.

**Remediation**
"Security through obscurity" - only to slow down basic attackers, efforts may be better on educating awareness.

**Useful Tools**
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) - Default in Kali
- [Wappalyzer](https://www.wappalyzer.com/) - Website and browser extension (has false positives and not as thorough but give likely indication)

---

### Map Application Architecture
It is important to map the network and application architecture to be able to perform an in-depth review.

**Test Objective:** Generate a map of the application through research conducted

Start with a "simple application" approach and look for:
- Reverse Proxies
  - Analysing the web server banner in the response
  - Analysing the response behaviour against known web app attacks
    - If a 404 is normally received when going to an unavailable page, but when a web attack is deployed it returns an error then we can suggest there is an application-level firewall or reverse proxy acting as an IPS.
  - If an app returns a set of available HTTP methods but some expected methods result in an error, something may be blocking them
- Firewalls 
  - no answer or ICMP unreachables received
  - an TCP Reset (RST) packet will be returned from non-listening ports if the server is internet connected
- Proxy caches
  - Time the requests and compare against the first request to subsequent ones
- Different servers
  - Examine multiple requests and determine if there are any discrepancies
    - Dates may not be synced
    - Headers may be different
    - Cookies may be different or contain prefixes
- Application web servers
  - Their responses will vary significantly (including different or additional headers)
  - It may set cookies
- Back-end Systems
  - LDAP directories, relational databases, or RADIUS servers
  - Difficult to identify externally
  - Existence can often be given away through the application eg. dynamic content
  - Detailed knowledge of the underlying database is normally only available through a vulnerable surface (eg. poor exception handling, SQLi)

Continue asking questions to build up the map, "what type?", "How is it configured?", "Could it be bypassed?"