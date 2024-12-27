```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

> A process of performing detailed searches across the file system and various applications to discover credentials.

**Four Primary Sources for Credentials**
Some examples of places we could look in each source.

| **Files**    | **History** | **Memory**           | **Key-Rings**              |
| ------------ | ----------- | -------------------- | -------------------------- |
| Configs      | Logs        | Cache                | Browser stored credentials |
| Databases    | CLI history | In-memory processing |                            |
| Notes        |             |                      |                            |
| Scripts      |             |                      |                            |
| Source Codes |             |                      |                            |
| Cronjobs     |             |                      |                            |
| SSH Keys     |             |                      |                            |
> Everything in linux is a file. So searching in files across the system can reveal critical insights (credentials, service config, databases etc).

## Configuration Files
Rarely but still possible, some services let you rename the config files, meaning that just searching for extensions isn't always all-encompassing.
```sh
# Find all files witn the any of the extensions, skipping the dirs at the end
$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Search for key words in any files matching the criteria
$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

## Databases
The same search ideas can be applied to database files.
```shell
$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

## Notes
Searching for notes is harder as they can be stored anywhere with any name. Often they will not have an extension or may include a `.txt` extension.
```sh
# find all files in the home/* dirs, that either have .txt or no extension (== '*.txt' or != '*.*')
$ find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

## Scripts
Scripts can be a great source for credentials as they often need credentials of higher privileges to perform actions automatically, they may even pull credentials from env vars too.
```sh
$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

> Cron jobs are also a useful place to check in `/etc/crontab` : `ls -la /etc/cron.*/`

## SSH Keys
As SSH private keys all contain standard headers in the files, we can still search for them across the system. SSH keys don't have to have any specific naming conventions so they are difficult to search on file names.
```sh
# Match against the first line of each file in the home dir for 'PRIVATE KEY'
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

# Public keys can also be found this way too
grep -rnw "ssh-rsa" /home/* 2>dev/null | grep ":1"
```

## History
### CLI History files
```sh
$ tail -n5 /home/*/.bash*
$ tail -n5 /home/*/*_history
$ tail -n5 /home/*/*rc
```

### Log Files
Many logs can exist on the file system, and logs are incredibly important in Linux systems. However, some key ones are:
- `/var/log/messages` : System activity logs
- `/var/log/syslog` : System activity logs
- `/var/log/auth.log` : (*Debian*) Auth related logs
- `/var/log/secure` : (*RH/CentOS*) Auth related logs
- `/var/log/boot.log` : Boot information
- `/var/log/dmesg` : Hardware and driver related logs
- `/var/log/kern.log` : Kernel logs
- `/var/log/faillog` : Failed login attempts
- `/var/log/cron` : Cronjob related logs
- `/var/log/mail.log` : Mail server logs
- `/var/log/httpd` : Apache related logs
- `/var/log/mysqld.log` : MySQL server related logs
> It is useful to be familiar with the structure of these logs, otherwise analysing each on individually would be inefficient. String matching can also be of value with logs to identify key information.

```shell
$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

## Memory and Cache
Many applications that work with credentials store them in-memory or in files to be reused later.
> [mimipenguin](https://github.com/huntergregal/mimipenguin) is a tool that is able to leak the credentials for users that are stored in-memory on a linux system (*requires root permissions*)

**LaZagne**
[Lazagne](https://github.com/AlessandroZ/LaZagne) is a tool (*worth keeping a standalone copy we can transfer over*) that can search for credentials that web browsers or other applications may install insecurely. The github page for the tool displays all the supported applications.

```sh
$ sudo python2.7 laZagne.py all
```
> `-vv` can be used to study what is happening in the background.

### Browsers
Many browsers store their 'saved' user credentials in encrypted files on the system, however, these are not necessarily safe.
```sh
# List the firefox files
ls -l .mozilla/firefox/ | grep default
```

Tools like [Firefox Decrypt](https://github.com/unode/firefox_decrypt) exist to break the encryption on these files. 
> This can also be done via LaZagne if it is a 'supported browser'
> `laZagne.py browsers`

