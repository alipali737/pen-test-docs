```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
WordPress is a Content Management System (CMS) that is very common still to this day. Majority of its vulnerabilities come from out-dated versions and vulnerable plugins.

Plugins, themes and WP core are the most common places to find vulnerabilities. (*Focus testing against the plugins*):
- ~4% WordPress Core
- ~89% Plugins
- ~7% Themes

## Identification
- Page sources contain `wp-content`, `themes`, `plugin` (Can be useful to grep for these words)
- `/robots.txt` likely contains `wp-*` directories
- Default login page `/wp-login.php`

```bash
curl -s https://example.com/ | grep plugins
curl -s https://example.com/ | grep themes
curl -s https://example.com/ | grep wp-content
```

## Useful Tools
### WPScan
[WPScan](https://github.com/wpscanteam/wpscan) is an automated scanner and enumeration tool for WordPress sites. WordPress also has extensive exploits in the [[Metasploit]] framework which can be very handy.
```bash
sudo gem install wpscan
```
For the tool to pull from external sources, we need to give it an API token for [WPVulnDB](https://wpvulndb.com/). It can be supplied with `--api-token`.

```bash
# Enumerate a site looking for WP components and potential vulnerabilities
sudo wpscan --url [target] --enumerate --api-token [token]
```

#### Login Bruteforce
There are two options in WPScan for login bruteforce: `wp-login` which is for the login page itself, and `xmlrpc` which attacks the WordPress API through `/xmlrpc.php` (*this is generally faster*).
```bash
sudo wpscan --password-attack xmlrpc -t [threads] -U [user(s)] -P [password(s)] --url [target]
```
