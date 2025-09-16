```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Document and Audit
Regular auditing and documentation of an AD environment is absolutely critical to an organisation's security posture. We should look to document and track:
- Naming conventions of OUs, computers, users, and group
- DNS, network, and DHCP configuration
- An intimate understanding of all GPOs and the objects that they are applied to
- Assignment of [[Active Directory#FSMO Roles|FSMO]] roles
- Full and current application inventory
- A list of all enterprise hosts and their location
- Any trust relationships with other domains or outside entities
- Users who have elevated permissions

## People
Humans continue to be the weakest link in any system, some suggestions for managing this risk are:
- Having a strong password policy
- Periodic password rotations for service accounts
- Disallow local administrator access on user workstations unless for specific business needs
- Disable the default `RID-500 local admin` account, make a new admin account subject to [[Active Directory#Password Rotation with LAPS|LAPS]]
- Split tiers of administrators based on needs (*no need for domain admin on an admin's normal workstation*)
- Clean up privileged groups, ensuring only membership that is absolutely necessary
- Disable kerberos delegation for administrative accounts
- Where appropriate, place accounts in the Protected Users group

## Protected Users Group
The [Protected Users group](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) first came in Windows Server 2012 R2. It restricts what members of the group can do in the domain, this can protect these users from being abused if compromised. The group provides a number of protections:
- Members cannot be delegated with constrained or unconstrained delegation
- CredSSP will not cache plaintext credentials in memory (*even if Allow delegating default credentials is set within Group Policy*)
- Windows Digest will not cache the user's plaintext passwords (*Even if Digest is enabled*)
- Members cannot authenticate using NTLM auth or use DES or RC4 Keys
- After acquiring a TGT, the user's long-term keys or plaintext credentials aren't cached
- Members cannot renew a TGT longer than the original 4-hour TTL
> The Protected Users group can have unforeseen authentication issues, thus its not a great idea to put all privileged users in this group without staged testing.

```PowerShell
Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members
```

## Processes
Having policies and processes can guide an organisation on how to act in certain situations (eg. Incident response plan, disaster recovery plan), it can also be used to hold employees accountable for their actions. 
- Proper policies and procedures for AD asset management
	- AD Host audit
	- The use of asset tags
	- Periodic asset inventories can help ensure a host isn't lost
- Access control policies (user account provisioning/de-provisioning), MFA mechanisms
- Processes for provisioning and de-provisioning hosts (eg. baseline security hardening guidelines, gold images)
- AD Clean up policies
	- Are accounts for former employees removed or just disabled?
	- What is the process for removing stale records in AD?
	- Processes for decommissioning legacy OS/services (eg. proper uninstallation of services)
	- Schedule for User, groups, and hosts audit

## Technology
Misconfigurations, legacy versions, new and emerging threats, and vulnerabilities introduced all contribute to weakening security in AD.
- Run tools such as [[BloodHound]], PingCastle, and Grouper periodically to identify AD misconfigurations.
- Ensure that administrators are not storing passwords in AD account description fields.
- Review SYSVOL for scripts containing sensitive data.
- Avoid the use of "normal" service accounts, utilising Group Managed (gMSA) and Managed Service Accounts (MSA) where every possible to mitigate the risk of kerberoasting (*specific types of account intended for service account usage*).
- Disable Unconstrained Delegation where possible.
- Prevent direct access to Domain Controllers through the use of hardened jump hosts.
- Consider setting the `ms-DS-MachineAccountQuota` to `0`, which disallows users from adding machine accounts and can prevent several attack such as [[Notable AD Attacks#NoPac (SamAccountName Spoofing) Standard domain access|noPac]] and Resource-Based Constrained Delegation (RBCD).
- Disable the print spooler service where possible.
- Disable NTLM authentication for DCs if possible.
- Use Extended Protection for Authentication along with enabling Require SSL only to allow HTTPS connections fro the Certificate Authority Web Enrolment and Certificate Enrolment Web Service services.
- Enable SMB signing and LDAP signing.
- Take steps to prevent enumeration with tools like BloodHound.
- Ideally, regularly perform penetration tests/AD security assessments.
- Test backups for validity and review/practice disaster recovery plans.
- Enable the restriction of anonymous access and prevent null session enumeration by setting the `RestrictNullSessAccess` registry key to `1` to restrict null session access to unauthenticated users.

## Enterprice ATT&CK Matrix
[Enterprise ATT&CK Matrix](https://attack.mitre.org/tactics/enterprise/)
> `TA` is an overarching tactic
> `T###` is a technique found in the matrix

- *External Recon* - `T1589` - Very hard to detect as it can be passive, make sure to control the data put out publicly about the company and scrum any documents before release so no internal information can be inferred.
- *Internal Recon* - `T1595` - Monitor network traffic, Firewalls and IDS/IPS (Deny ICMP traffic to help prevent information being discovered)
- *Poisoning* - `T1557` - SMB message signing and encrypting traffic can help stop poisoning & MiTM attacks
- *Password Spraying* - `T1110/003` - Logging and monitoring can highlight this, events: `4624` and `4648` get raised a lot. Password policies and posture is very important here
- *Credentialed Enumeration* - `TA0006` - Monitoring for unusual activity from user accounts: movement of files, multiple RDP requests etc can all help tip off defenders
- *LOTL* - `N/A` - Harder to spot but can be compared to user behaviour and baseline network traffic. Watch for command shells
- *Kerberoasting* - `T1558/003` - Use strong encryption schemes, use Group Managed service accounts, periodic auditing of permissions and group memberships