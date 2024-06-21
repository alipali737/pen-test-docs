---
layout: page
title: 
parent: 
grand_parent:
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

OS injection vulnerabilities allow an attacker to execute OS level commands on the system that the application is running on. These vulnerabilities are most often caused by a lack of input sanitisation.

## Attack Motivation
- Full system takeover
- Denial of Service
- Stolen sensitive information
- Lateral movement on the network
- Use of system for botnets or crypto-mining

## Prevention
- **Never execute OS commands** - OS Exec is most likely overkill
	- Use libraries and programatic methods
	- Using library functions significantly reduce the *attack surface*
- Run the app at the **least possible privilege level**
- **Do not run commands through shell interpreters**
	- Eg. `/bin/sh -c "/bin/rm /var/app/logs/x;rm -rf /"` would allow injection
	- Whereas `/bin/rm /var/app/logs/x;rm -rf /` would fail the whole command, not allowing the injection
- Use **explicit paths** when running executables
	- eg. `nmap 123.45.67.89` could allow an attacker to hijack the executable by supplying another one (DLL Hijacking)
	- instead, use `/usr/bin/nmap 123.45.67.89`
- **Do not let user input reach command execution unchanged**
	- Make sure to sanitise inputs before using them
	- eg. if a user was to try delete a file, have a translation table that maps the display name to the actual filename
- **Sanitise user input** with strict allow lists
	- File names could be *[A-Za-z0-9.]+*

