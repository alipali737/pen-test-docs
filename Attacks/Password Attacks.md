```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 4 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Credential Storage
### Linux
> [Linux User Auth](https://tldp.org/HOWTO/pdf/User-Authentication-HOWTO.pdf)

#### /etc/shadow
>Should only be readable by `root`

The shadow file contains all the hashes of user passwords:
```sh
cat /etc/shadow

htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```
The format for the string (*separated by `:`*) goes as:
1. Username (*htb-student*)
2. Password Hash (*\$y\$j9T\$3...f8Ms*)
3. Day of last change in unix time (*18955* - days after 1st Jan 1970)
4. Minimum Age in days before the next change can occur (*0*)
5. Maximum Age in days until the next change has to occur (*99999*)
6. Warning period in days before password expires (*7*)
7. Inactivity period is days after password expires before acc is disabled (*:*)
8. Expiration date as days after 1st Jan 1970 (*:*)
9. Reserved field (*:*)
The hash is comprised of 3 parts (*separated by `$`*):
1. Algorithm ID (*\$y*)
2. Salt (*\$j9T*)
3. Hash (*$3QSBB...f8Ms*)
Each algorithm ID corresponds to a hashing algorithm:
- *$1* - MD5
- *$2a* - Blowfish
- *$5* - SHA-256
- *$6* - SHA-512
- *$sha1* - SHA1crypt
- *\$y* - Yescrypt
- *$gy* - Gost-yescrypt
- *$7* - Scrypt

#### /etc/passwd
> Should only be writable by root

This file contains all the user accounts and some information about them:
```shell
cat /etc/passwd

htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```
1. Username (*htb-student*)
2. Password (*x* means it is encrypted in the shadow file, if this is blank it means no password is required - if a user can edit this they can disable the password auth etc)
3. uid (*1000*)
4. gid (*1000*)
5. comment (*,,,*)
6. home dir (*/home/htb-student*)
7. cmd to run after login (*/bin/bash*)

### Windows
