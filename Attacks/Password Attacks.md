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
> A local interactive login (a user logging into the system locally) utilises the logon process (`WinLogon.exe`), the logon user interface process (`LogonUI`), the `credential providers`, `LSASS`, one or more `authentication packages`, and [[Windows#Security Account Manager (SAM)|SAM]] or `AD`.
> Authentication packages are often DLLs that perform authentication checks (non-domain joined and interactive logins is handled by `Msv1_0.dll`).

#### WinLogon
Handles security-related user interactions, including:
- Launching LogonUI to enter password
- Changing passwords
- Locking and unlocking the system
It relies on credential providers *(`COM` objects in DLLs)* on the system to obtain usernames and passwords.
WinLogon is the only process to accept logon requests from the keyboard, sent via [[SMB#RPCclient|RPC]] from `Win32k.sys`.
![[Pasted image 20241218090302.png]]
#### Credential Manager
This feature allows users to save credentials for various network resources and websites. Credentials are stored in each user's `Credential Locker`, which is then encrypted and saved to `C:\Users\[user]\AppData\Local\Microsoft\[Vault/Credentials]`.
#### Local Security Authority Server Service (LSASS)
[Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) (*LSASS*) is a collection of modules and authentication processes. The service is responsible for:
- the local system security policy
- user authentication
- security audit logging to the `Event log`
> Detailed architecture [here](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN)

| Authentication Packages | Description                                                                                                                                              |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Lsasrv.dll              | LSA Server service - enforces security policies and acts as the security package manager for LSA. Also selects whether to use NTLM or Kerberos protocol. |
| Msv1_0.dll              | Authentication package for local machine logons that don't require custom authentication.                                                                |
| Samsrv.dll              | The [[Windows#Security Account Manager (SAM)\|SAM]] stores local security accounts, enforces locally stored policies, and supports APIs.                 |
| Kerberos.dll            | Security package for Kerberos-based authentication.                                                                                                      |
| Netlogon.dll            | Network-based logon service.                                                                                                                             |
| Ntdsa.dll               | Library used to create new record and folders in the Windows Registry                                                                                    |
#### Security Account Manager (SAM)
![[Windows#Security Account Manager (SAM)]]

## Common Password Combinations
A really important piece of information for speeding up cracking passwords is understanding the password policy implemented, what criteria does a password have to meet?
A lot of the time a password is asked to meet:
- Must contain a number
- Must contain a symbol
- Must be 8+ chars
- Must contain both lowercase and upper case
Often these accommodations are made by users
- `a -> @`
- `e -> 3`
- `s -> 5`
- `!` at the end
- Capital at the start
- `1` or `123` at the end

A pretty common format for a user to do is:
- Capital at the start
- Single word
- `!` at the end

The [DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) contains a list of many default credentials for common applications, often these default credentials can be forgotten or overlooked when configuring infrastructure which can lead to easy access of the system.

## Attacking SAM
> Ref: [[Windows#Security Account Manager (SAM)]]

