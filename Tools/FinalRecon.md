```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*FinalRecon* is a python-based tool that offers a variety of modules (incl. SSL cert verification, Whois, header analysis, and crawling). Some of its key information gathering techniques include:
- *Header information analysis* : reveals server details, technologies, and potential security misconfigurations
- *Whois lookup* : uncover domain registration details & contacts
- *SSL certificate information* : examine the SSL cert for validity, issuer, and other details
- *Crawler* : extract potentially sensitive information / files & uncover hidden sections of websites
- *DNS enumeration* : query the domain for DNS records to reveal other hosts (include DMARC records for email security assessments)
- *Subdomain enumeration* : utilises a variety of data sources to discover subdomains relating to the target
- *Directory enumeration* : supports custom wordlists and file extensions to uncover hidden directories and files
- *Wayback Machine* : identifies URLs for previous iterations of the websites to analyse its changes and potential vulnerabilities

## Installation
```sh
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help
```

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/thewhiteh4t/FinalRecon
## Usage
```sh
./finalrecon.py --full --url [target_url]
```

| Flag        | Description                                         |
| ----------- | --------------------------------------------------- |
| `--url`     | specify the target URL                              |
| `--headers` | retrieve the header information from the target URL |
| `--sslinfo` | get ssl cert info                                   |
| `--whois`   | perform a whois lookup on the target domain         |
| `--crawl`   | crawl the target website                            |
| `--dns`     | perform a DNS enumeration on the target domain      |
| `--sub`     | enumerate subdomains for the target domain          |
| `--dir`     | perform a directory enumeration                     |
| `--wayback` | retrieve the Wayback URLs for the target            |
| `--ps`      | perform a fast port scan on the target              |
| `--full`    | perform a full recon (all modules) on the target    |
