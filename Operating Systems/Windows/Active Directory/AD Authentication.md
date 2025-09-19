```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## The 'Double Hop' Problem
When we use passwords to authenticate, that NTLM hash is stored in our session. Storing the hash in the session allows us to seamlessly pass it between resources for further authentication (*during lateral movement for example*). However, Kerberos tickets are instead tied to a specific resource and cannot be reused for other resources. This introduces the double hop problem.

The issue often occurs when using WinRM/Powershell since the default authentication method only provides a ticket to access a specific resource. Although we may have the correct rights to view additional resources, we may still be denied if we present this kerberos ticket (*eg. the ticket gives us access to a host, but we want to then access a remote share from that host*).

Often, we gain an initial shell by targeting an application on a single host or using credentials with a tool such as `PSExec`. These both would very likely perform authentication over SMB or LDAP, meaning the user's NTLM hash would be stored in memory. However, when we use WinRM to authenticate over two or more connections, the user's password is never cached as we are using Kerberos tickets rather than a password for authentication.

**Network Authentication Process**
1. ATK-HOST connects to DEV-01 using [[Evil-Winrm]]
2. This passes the user's [[Kerberos#Ticket Granting Service (TGS)|TGS]] to the DEV-01 system but not the [[Kerberos#Ticket Granting Ticket (TGT)|TGT]] (which would be used to generate subsequent tickets for other resources)
3. When DEV-01 attempts to communicate with DC-01 using `PowerView`, it is denied.
4. As no TGT was provided in the first hop, DEV-01 cannot create any new tickets for the user so we aren't able to use the user's context on DC-01

> If a server has `unconstrained delegation` enabled, then the user's TGT is sent and cached on the target machine so the double hop problem doesn't occur.

### Workaround - PSCredential Object
If we connect to a remote server (`academy-aen-ms0`) with domain credentials, then try to run PowerView (*which interacts with another server - the DC*):
```PowerShell
*Evil-WinRM* PS C:\Users\backupadm\Documents> import-module .\PowerView.ps1

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn
Exception calling "FindAll" with "0" argument(s): "An operations error occurred.
"
At C:\Users\backupadm\Documents\PowerView.ps1:5253 char:20
+             else { $Results = $UserSearcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : DirectoryServicesCOMException
```

We can see that we get an error as we can't pass our authentication to the DC. We can also prove we only have the TGS ticket cached on the machine:
```PowerShell
*Evil-WinRM* PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x57f8a

Cached Tickets: (1)

#0> Client: backupadm @ INLANEFREIGHT.LOCAL
    Server: academy-aen-ms0$ @ # <-- This shows the name of the machine this ticket is for, its the one we connected too. Its not a TGT
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0xa10000 -> renewable pre_authent name_canonicalize
    Start Time: 6/28/2022 7:31:53 (local)
    End Time:   6/28/2022 7:46:53 (local)
    Renew Time: 7/5/2022 7:31:18 (local)
    Session Key Type: AES-256-CTS-HMAC-SHA1-96
    Cache Flags: 0x4 -> S4U
    Kdc Called: DC01.INLANEFREIGHT.LOCAL
```

To get around this, we can create a PSCredential object that contains our user's credential and then pass that with PowerView:
```PowerShell
*Evil-WinRM* PS C:\Users\backupadm\Documents> $SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\backupadm\Documents> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)

*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn -credential $Cred | select samaccountname
```

### Workaround - Register PSSession Configuration
Sometimes we don't want to or a tool doesn't let us provide a PSCredential object, so instead we can register a PSSession. If we are already on a domain-joined windows host, then we can use the existing information about our session. If we connect to the first host
```PowerShell
Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm
```
We are now connected to the first host but we are in the same issue as before, we don't have a cached TGT. To resolve this, we can register a new session configuration using [Register-PSSessionConfiguration](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/register-pssessionconfiguration?view=powershell-7.2).
```PowerShell
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
```
We then need to restart our session with `Restart-Service WinRM` in our current PSSession and enter into the new session.
```PowerShell
Restart-Service WinRM
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName backupadmsess
```
Now our TGT will be cached and we can interact with other resources.

We can also use the PSCredentials like above and PSSession together:
```PowerShell
$user = "[domain]\[user]"  
$Password = ConvertTo-SecureString "[pass]" -AsPlainText -Force  
$credentials = New-Object System.Management.Automation.PSCredential ($user, $Password)
Enter-PSSession -ComputerName "[target]" -Credential $credentials
```
## Kerberos
![[Kerberos#Summary]]
![[Kerberos#How it works]]

## NTLM Authentication
NTLMv1 & NTLMv2 are authentication protocols that deal with NTLM (NT) and LM hashes. Although not perfect, [[Kerberos]] is often the preferred choice for AD authentication when compared with the other options:

| Hash/Protocol  | Cryptographic Technique                              | Mutual Authentication | Message Type                    | Trusted Third Party   |
| -------------- | ---------------------------------------------------- | --------------------- | ------------------------------- | --------------------- |
| *NTLM*         | Symmetric key cryptography                           | No                    | Random number                   | Domain Controller     |
| *NTLMv1*       | Symmetric key cryptography                           | No                    | MD4 Hash, Random number         | Domain Controller     |
| *NTLMv2*       | Symmetric key cryptography                           | No                    | MD4 Hash, Random number         | Domain Controller     |
| *[[Kerberos]]* | Symmetric key cryptography & asymmetric cryptography | Yes                   | Encrypted ticket using DES, MD5 | Domain Controller/KDC |

[Windows New Technology LAN Manager (NTLM)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview) is a set of security protocols that authenticates users' identities while also protecting integrity and confidentiality of their data. 

NTLM is an SSO solution that utilises a challenge-response protocol to verify user identities without having a password provided each time. 

NTLM has many flaws but it is still commonplace to ensure compatibility with legacy systems whilst still being the preferred method on modern systems. 

Whilst still supported, Kerberos has taken over at the default auth system for modern systems (Windows 2000+ AD domains). 

*Passwords are stored on the server or domain controller but are NOT salted!* This can be exploited via a [[Password Attacks#Pass-the-Hash|Pass-the-Hash (PtH)]] attack.

> An NTLM is also sometimes referred to by `RC4-HMAC`.
### LM
LAN Manager (*LM*) hashes are the oldest password storage mechanism in Windows. If in use, they are stored in the [[Windows#Security Account Manager (SAM)|SAM]] database on a host and the [[Windows#NTDS|NTDS.dit]] db on the Domain Controller. (*it is disabled by default due to security weaknesses*)
> LM hash usage can be disallowed via [[#Group Policy Object (GPO)|Group Policy]]

LM Passwords are:
- *limited to 14 characters*
- *not case sensitive* (they are uppercased before being hashed)
- maximum keyspace of 69 characters

**Hashing Method**
1. A 14 char password is split into two seven-char chunks.
	1. `NULL` chars are added to pad the password to 14 chars
2. Two DES keys are created from each chunk
3. These chunks are then encrypted with the string `KGS!@#$%` to create two 8-byte ciphertexts.
4. The two values are then concatenated together to create the final LM hash.

> This means that a brute force actually only needs to match two seven character strings. If we are using parallelism this can be incredibly easy. 

### NTHash (NTLM)
*NT LAN Manager* (NTLM) hashes are used in modern Windows systems. It is a challenge-response authentication protocol:
1. NTLM `NEGOTIATE_MESSAGE` (client -> server)
2. NTLM `CHALLENGE_MESSAGE` (server -> client) : challenge to verify the client's identity
3. NTLM `AUTHENTICATE_MESSAGE` (client -> server)
4. `Netlogon_network_info` (client -> server)
5. `Netlogon_Validation_SAM_info` (server -> client)

These hashes are stored in the [[Windows#Security Account Manager (SAM)|SAM]] database on a host and the [[Windows#NTDS|NTDS.dit]] db on the Domain Controller. NTLM supports the use of [[#LM]] hashes and the NT hash (*MD4 hash of the little-endian UTF-16 value of the password - `MD4(UTF-16-LE(password))`*).

It can be possible to brute force the entire NTLM 8 character keyspace in under *3 hours*. Dictionary attacks and rules can make longer passwords vulnerable still. NTLM is also vulnerable to [[Password Attacks#Pass-the-Hash|Pass-the-Hash]] attacks.

**Format:**
```
<user>:<RID>:<LM>:<NT>:::
```


### NTLMv1 (Net-NTLMv1)
NTLMv1 differs from the modern NTLM protocol as it uses both the NT and the LM hash, meaning it can be easier to crack offline if captured. It is designed for network authentication. The hashes produced by this algorithm can NOT be used for PtH.

```
SC = 8-byte random number
K1 | K2 | K3 = LM/NT-hash | 5-bytes-0
response = DES(K1, SC) | DES(K2, SC) | DES(K3, SC)
```

### NTLMv2 (Net-NTLMv2)
A stronger alternative to *NTLMv1*. The client sends two responses to the challenge (8-byte random number) from the server: 
- a 16-byte HMAC-MD5 hash of the challenge + a random challenge generated by the client + a HMAC-MD5 hash of the user's credentials
- Variable length client challenge including the time, an 8-byte random challenge value (`CC2`), and the domain name

```
SC = 8-byte random number
CC = 8-byte random number
CC* = (X, time, CC2, domain)
v2-Hash = HMAC-MD5(NT-Hash, username, domain name)
LMv2 = HMAC-MD5(v2-Hash, SC, CC)
NTv2 = HMAC-MD5(v2-Hash, SC, CC*)
response = LMv2 | CC | NTv2 | CC*
```

## Domain Cached Credentials (MSCache2)
In an AD environment, most authentication methods such as [[#NTLM Authentication]] all require the host to communicate with the Domain Controller. The [MS Cache v1 and v2](https://webstersprodigy.net/2014/02/03/mscash-hash-primer-for-pentesters/) (AKA *Domain Cached Credentials - DCC*) solves the potential issue where a domain-joined host cannot communicate with the DC, thus, NTLM/Kerberos authentication wouldn't work.

With DCC, the host caches the last *ten* hashes for any domain users that successfully log into the machine in the `HKEY_LOCAL_MACHINE\SECURITY\Cache` registry key. These hashes however, cannot be used for a [[Password Attacks#Pass-the-Hash|PtH]] attack and they are incredibly slow to crack.

Its important to watch out for these hashes as they are a waste of time to attempt to crack:
```
$DCC2$10240#jsmith#e4e9...c90f
```
