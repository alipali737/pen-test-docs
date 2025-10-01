```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
The `.well-known` directory is used for commonly requested information about the website. The URIs are defined by the *Internet Assigned Numbers Authority* (*IANA*) [registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml). These could be configuration files, or information relating to services, protocols or security mechanisms. the `/.well-known/` path on a web server centralises a website's critical metadata. Some notable URIs are:

| URI Suffix             | Description                                                                                     | Status      | Reference                                                                               |
| ---------------------- | ----------------------------------------------------------------------------------------------- | ----------- | --------------------------------------------------------------------------------------- |
| *security.txt*         | Contains contact information for security researchers to report vulnerabilities                 | Permanent   | RFC 9116                                                                                |
| *change-password*      | Standard url for users to change their password                                                 | Provisional | https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri |
| *openid-configuration* | Configuration details for OpenID Connect (a layer on top of the OAuth 2.0 protocol)             | Permanent   | http://openid.net/specs/openid-connect-discovery-1_0.html                               |
| *assetlinks.json*      | Verify ownership of digital assets associated with a domain                                     | Permanent   | https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md     |
| *mta-sts.txt*          | Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security | Permanent   | RFC 8461                                                                                |
