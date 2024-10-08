```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

This process aims to go from a low privilege user to a full privilege user (`root / administrator / SYSTEM`).

## Checklists
Its useful to have checklists to follow through for this process. [HackTricks](https://book.hacktricks.xyz/) & [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) are both great resources for these checklists.

## Enumeration Scripts
Many privilege exploits can be automated and scripts can enumerate through possibilities. These can be very noisy so sometimes manual investigation is better for more evasive intentions.
![[Useful Resources#PrivEsc]]

## Kernel Exploits
If the server is using an old OS version, then there are potentially kernel exploits available for PE. We can find this version out from `uname -a`. *These can have major consequences on the system's stability*, so care should be taken to try these in a lab first then (with client permission if its a prod environment) run it on the real system.

## Vulnerable Software
Exploring the packages & software installed on the system could give some valuable vectors for PE:
- Linux : `dpkg -l`
- Windows : `C:\Program Files`

## User privileges
We should check what permissions we actually have to start with and whether they can be abused. Some common ways:
- Sudo : `sudo -l`
- SUID
- Windows Token Privileges

## Scheduled Tasks / Cron Jobs
There are usually two ways this can be exploited for PE:
- Add a new job which runs our code
- Modify an existing one to run our code

The easiest way in Linux to check if we can create cron jobs, we need *write* access to any of:
- /etc/crontab
- /etc/cron.d
- /var/spool/cron/crontab/root

If we can write to a directory that is called by a cronjob, we can execute a reverse shell command.

## Exposed Credentials
Just looking through files (eg. configs, logs, user history etc), we can potentially find exposed credentials. Many users use the same password regularly so we can try it in other places too.

## SSH Keys
If we have read access over an ssh directory we might be able to find private keys. If we have write access we can put our public key in there to give us persistent access to that user.