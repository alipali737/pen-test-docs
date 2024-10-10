```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
SSL certificates verify the authenticity of a website. 

## Issuing a Certificate
Certificates are ultimately monitored and audited by the public through transparency.
1. A website requests a new certificate from a *Certificate Authority* (*CA*).
2. The *CA* vets the website's request, and authenticates the requester is who they say they are.
3. Once authenticated, the *CA* provides a *pre-certificate* to the website (a preliminary version of the certificate).
4. The *CA* also sends the pre-certificate to multiple *Certificate Transparency* (*CT*) logs (independent companies that hold an append-only public log of all issued certificates).
5. The *CT*s then send back a *Signed Certificate Timestamp* (*SCT*), confirming the certificate has been added to the logs. These *SCT*s are then added to make the final certificate.
6. A user's browser verifies these *SCT*s by checking the logs for their accuracy and warns a user if they fail.
7. The public is then able to monitor and audit these *CT* logs for suspicious certificates and notify *CA*s for investigations.

## Enumerating Subdomains Through CT Logs
As CT logs hold a public log of all subdomain certs for a particular base domain, we can accurately identify all subdomains of a particular target that have certificates. This can also highlight any with old or expired certificates (potentially indicating out-dated software and vulnerabilities). With CT logs, there is no need to brute-force or rely on the completeness of wordlists.

|Tool|Key Features|Use Cases|Pros|Cons|
|---|---|---|---|---|
|[crt.sh](https://crt.sh/)|User-friendly web interface, simple search by domain, displays certificate details, SAN entries.|Quick and easy searches, identifying subdomains, checking certificate issuance history.|Free, easy to use, no registration required.|Limited filtering and analysis options.|
|[Censys](https://search.censys.io/)|Powerful search engine for internet-connected devices, advanced filtering by domain, IP, certificate attributes.|In-depth analysis of certificates, identifying misconfigurations, finding related certificates and hosts.|Extensive data and filtering options, API access.|Requires registration (free tier available).|

```shell
curl -s "https://crt.sh/?p=[target_domain]&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://crt.sh/?p=[target_domain]&output=json" | jq -r '.[] | select(.name_value | contains("[target_substring]")) | .name_value' | sort -u
```