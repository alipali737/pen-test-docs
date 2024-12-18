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
Windows [Windows client authentication process](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication) tends to be more complicated than with Linux systems, consisting with many different modules that the various processes required to authenticate a client. Additionally, there are many different authentication processes, such as Kerberos auth.
![[Windows#Local Security Authority (LSA)]]
![[Pasted image 20241218082951.png]]
> A local interactive login (a user logging into the system locally) utilises the logon process (`WinLogon.exe`), the logon user interface process (`LogonUI`), the `credential providers`, `LSASS`, one or more `authentication packages`, and `SAM` or `AD`.
> Authentication packages are often DLLs that perform authentication checks (non-domain joined and interactive logins is handled by `Msv1_0.dll`).

#### WinLogon
Handles security-related user interactions, including:
- Launching LogonUI to enter password
- Changing passwords
- Locking and unlocking the system
It relies on credential providers *(`COM` objects in DLLs)* on the system to obtain usernames and passwords.
WinLogon is the only process to accept logon requests from the keyboard, sent via [[SMB#RPCclient|RPC]] from `Win32k.sys`.
1. `WinLogon` is called, which in-turn, launches the `LogonUI` for the user to enter their credentials.
2. Once a username & password have been obtained by the `credential provider`, the `lsass` process is called to authenticate the attempt.
#### Local Security Authority Server Service (LSASS)
[Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) (*LSASS*) is a collection of modules and authentication processes. The service is responsible for:
- the local system security policy
- user authentication
- security audit logging to the `Event log`
> Detailed architecture [here](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN)

| Authentication Packages | Description |
| ----------------------- | ----------- |
| Lsasrv.d                |             |