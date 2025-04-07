```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

A directory service for windows network environments. Provides centralised management of resources, users, devices etc. It provides *authentication*, *accounting*, and *authorization* functions within an enterprise Windows environment.

AD was first released with Windows Server 2000 and has been improved incrementally since. It is based on the `x.500` and `LDAP` protocols (*still using them in some capacity to this day*). It is designed to be *backwards compatible* and many features are arguably not "secure by default".

It's essentially a read-only database that *any user* (regardless of privilege) can enumerate, meaning it can be searched for potentially exploitable misconfigurations. It is extremely important to properly secure an AD implementation (network segmentation, least privilege, hardening etc), many attacks can be done as a standard domain user account.

AD specifically requires LDAP ([[Kerberos]]), [[DNS]], and RPC ([[SMB & RPC#MSRPC / RPCclient|MSRPC]]) for its authentication and communication needs.

## Active Directory Structure
AD is a hierarchical tree structure, with a forest a the top containing one or more domains, these can then have nested subdomains.

A very simplistic high level structure for an AD may look like:
```
INLANEFREIGHT.LOCAL/       <-- Forest
├── ADMIN.INLANEFREIGHT.LOCAL  <-- Tree
│   ├── GPOs
│   └── OU  <-- Organisational Unit
│       └── EMPLOYEES      <-- Container
│           ├── COMPUTERS
│           │   └── FILE01     <-- Leaf
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

### Forests (Root Domains)
Forests are the top level element of the AD structure, forests can:
- Contain multiple domains
- Include child/sub domains
- Control all objects under its security boundary
Forests are a domain structure within which contained objects (users, computers, and groups) are accessible. It has many built-in Organisational Units (OUs), such as *Domain Controllers*, *Users*, *Computers*, and new OUs can be created as required. OUs can contain objects and sub-OUs, allowing for the assignment of different group policies.

It is common to see multiple domains (or forests) linked together via a *trust relationship* in organisations that perform a lot of acquisitions. It is often quicker and easier to create a trust relationship with another domain/forest than recreate all the objects in the current domain.

![[Pasted image 20250228100259.png|800]]
> This is an example of a trust relationship between two domains. This means that any users in either `inlanefrieght.local` or `freightlogistics.local` can access any of the sub domains below either one. True
> HOWEVER, if a user lower down in the chain, eg. `admin.dev.inlanefrieght.local` was created, they would NOT be able to access anything else (even within the same domain) as you can only access down the tree. If you wanted to access `wh.corp.inlanefreight.local` for example, a trust relationship would need to be setup between them. 
#### Trusts
Trusts can be used for *forest-forest* or *domain-domain* authentication, allowing users to interact with resources outside their domain. A trust links two domains.

Trusts can be transitive (*extended to objects that the child domain trusts*) or non-transitive (*only the child domain is trusted*). They can also be one-way (*only users in the trusted domain can access resources in the trusting domain, not vice-versa - the direction of trust is opposite to the direction of access*), two-way (*bidirectional*) allows access for both.

Trusts, if setup improperly, can provide unintended attack paths. Mergers and acquisitions can result in bidirectional trusts which could unknowingly introduce risk into the acquiring company's environment. It isn't uncommon to see *Kerberosting* against a domain outside the principal domain to obtain administrator accounts within the principal domain.

- *Parent-Child* : Domains within the same forest, the child has a two-way transitive trust with the parent domain
- *Cross-link* : A trust between child domains to speed up authentication
- *External* : A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilises SID filtering.
- *Tree-root* : A two-way transitive trust between a forest root domain and a new tree root domain.
- *Forest* : A transitive trust between two forest root domains.
![[Pasted image 20250228135859.png|700]]
> If the cross-link trust between `shippinglanes` & `dev.inlanefreight` was one-way, then only members of `shippinglanes` could access `dev.inlanefreight` resources, not the other way around.

### Objects
Any resource present in an AD environment, eg. OUs, printers, users, domain controllers are all Objects

### Attributes
Every object in an AD has an associated set of [attributes](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all) used to define its characteristics. Eg. the computer object has attributes such as hostname and DNS name.

### Schema
The AD [schema](https://docs.microsoft.com/en-us/windows/win32/ad/schema) is essentially the blueprint for any enterprise environment. It defines what types of objects and their associated attributes exist. It holds definitions for AD objects and holds the information for each object. Eg. user objects in the AD belong to the *users* class in the schema.

### Tree
A collection of AD domains that begins at a single root domain. A forest is a collection of trees. Eg. `dev.inlanefrieght.local-->admin.dev.inlanefreight.local` is a tree, and `inlanefreight.local` is the forest as it is the root.

### Container
Container objects hold other objects and have a defined place in the directory subtree hierarchy.

### Leaf
Leaf objects do not contain other objects and are found at the end of the subtree

## Terminology 

### Global Unique Identifier (GUID)
A 128-bit value assigned when a domain object is created. It is unique across the enterprise, similar to a MAC address. It is stored in the *objectGUID* attribute.

### Security Principals
[Security principals](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals) are anything that the operating system can authenticate, including users, computer accounts, or processes that run as a user. In AD, security prinipals are domain objects that manage access to other resources in the domain. [[Windows#Security Account Manager (SAM)|SAM]] can be used to manage local user accounts and security groups on a single computer but this won't be AD managed then.

### Security Identifier (SID)
A [[Windows#Security Identifier (SID)|SID]] is a unique identifier for a security principal or security group. In AD, it is issued by the domain controller. It is contained within the authentication token received by a user when they log in. It is then used to check access rights. [well-known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) are used to identify generic users and groups.

### Distinguished Name (DN)
A [Distinguished Name (DN)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names) describes the full path to an object in AD (`cn=jsmith, ou=IT, ou=Employees, dc=inlanefreight, dc=local` is effectively `inlanefrieght.local/Employees+IT/jsmith`). *Its LDAP*.

### Relative Distinguished Name (RDN)
A [Relative Distinguished Name (RDN)](https://docs.microsoft.com/en-us/windows/win32/ad/object-names-and-identities) is a single component of the DN that identifies the object as unique from other objets at the current level. Eg. `jsmith` is the RDN of the object. The RDN must be unique in an OU.

### sAMAccountName
The [sAMAccountName](https://docs.microsoft.com/en-us/windows/win32/ad/naming-properties#samaccountname) attribute is the user's logon name. It must be unique and <= 20 chars.

### userPrincipleName
The [userPrincipalName](https://social.technet.microsoft.com/wiki/contents/articles/52250.active-directory-user-principal-name.aspx) attribute is the `<user-account-name>@<domain-name>` : `jsmith@inlanefreight.local` (*it is not mandatory*)

### FSMO Roles
[Flexible Single Master Operation (FSMO)](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles) roles give Domain Controllers (DC)s the ability to continue authenticating users and granting permissions without interruption. All 5 roles are assigned to the first DC in the forest root domain in a new AD forest. Each time a new domain is added, on the RID Master, PDC Emulator and Infrastructure Master roles are assigned to the new domain. FSMO roles are typically set when domain controllers are created, but sysadmins can transfer these roles if needed. FSMO issues can lead to authentication and authorisation difficulties within a domain.

There are 5 FSMO roles:
#### Schema Master
- Manages the read/write copy of the AD schema
#### Domain Naming Master (*One for each forest*)
- Manages domain names and ensures that two domains of the same name are not created in the same forest
#### Relative ID (RID) Master (*One per domain*)
- Assigns blocks of RIDs to other DCs within the domain that can be used for new objects.
- Ensures that multiple objects aren't assigned the same SID.
- The domain object SIDs are the domain SID combined with the RID number for the object.
#### Primary Domain Controller (PDC) Emulator (*One per domain*)
- The host with this role is the authoritative DC in the domain and would respond to authentication requests, password changes, and manage GPOs.
- Also maintains time within the domain.
#### Infrastructure Master (*One per domain*)
- Translates GUIDs, SIDs, and DNs between domains.
- Used when multiple domains are within a single forest, enabling communication between them.
- If this role isn't functioning correctly, ACLs with show SIDs instead of fully resolved names.

### Global Catalog
A [global catalog (GC)](https://docs.microsoft.com/en-us/windows/win32/ad/global-catalog) is a domain controller that stores copies of ALL objects in an AD forest. It stores full copies of any object within its domain, and partial copies of objects in any other domains in the forest. A normal domain controller only stores info about its own objects, meaning that a GC can be used to query info about any object within any domain in the forest.

### Read-Only Domain Controller (RODC)
Essentially a read-only AD database. An [Read-Only Domain Controller (RODC)](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema) has no AD account passwords in its cache other than its own credentials. They can also be used to:
- have a read-only DNS server
- allow administrator role separation
- reduce replication traffic
- prevent SYSVOL modifications from being replicated to other DCs

### Replication
[Replication](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts) happens when AD objects are updated and transferred from one DC to another. Connection objects are created, *by the Knowledge Consistency Checker (KCC) running on every DC*, whenever a new DC is added to facilitate replication. This syncs changes to all DCs in a forest for DR.

### Service Principal Name (SPN)
A [Service Principal Name (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) uniquely identifies a service instance. They are used by Kerberos authentication to associate an instance of a service with a logon account.

### Group Policy Object (GPO)
[Group Policy Objects (GPOs)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects) are virtual collections of policy settings. Each GPO has a GUID and can contain local file system or AD settings. They can be applied to users and/or computer objects. They can be applied globally in a domain or granularly at the OU level.

### Access Control List (ACL)
An [Access Control List (ACL)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) is an ordered collection of Access Control Entries (ACEs) that apply to an object.

### Access Control Entries (ACEs)
Each [Access Control Entry (ACE)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-entries) in an ACL identifies a trustee (user acc, group acc, or logon session) and lists their rights (allowed, denied, or audited).

### Discretional ACL (DACL)
DACLs define which security principals are granted or denied access to an object; it contains a list of ACEs. When a process tries to access a securable object, the system authorises based on the DACL.

### System ACL (SACL)
Allows admins to log access attempts that are made to secured objects. ACEs specify the types of access attempts that cause the system to generate a record in the security event log.

### Fully Qualified Domain Name (FQDN)
An FQDN is the complete name of a computer or host. `<hostname>.<domain>.<tld>` used to specify an object's location in the DNS tree. Used to locate a host in AD without knowing the IP.

### Tombstone
A [tombstone](https://ldapwiki.com/wiki/Wiki.jsp?page=Tombstone) is a container object in AD that holds deleted AD objects. When an object is deleted from AD, the object remains for a set period of time known as the *Tombstone Lifetime*, and *isDeleted* is set to `True`. Once the lifetime is exceeded, the object is entirely removed. Defaults to 60 or 180 days depending on DC OS version. When an object is deleted in an AD environment without an AD Recycle Bin, it will become a tombstone object. Majority of its attributes will be stripped and it will be places in the *Deleted Objects* container for its lifespan. It can be recovered by any stripped attributes can't.

### AD Recycle Bin
If an object is deleted it goes to this bin for a set period (default 60 days). It is much easier to fully restore the object than from a tombstone.

### SYSVOL
The [SYSVOL](https://social.technet.microsoft.com/wiki/contents/articles/8548.active-directory-sysvol-and-netlogon.aspx) folder, or share, stores copied of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, and often contains other types of scripts used in the AD environment. The contents of this folder is replicated to all DCs using File Replication Services (FRS).

### AdminSDHolder
The [AdminSDHolder](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) object is used to manage ACLs for members of built-in groups in AD marked as privileged. Its a container for the Security Descriptor applied to members of protected groups. The `SDProp` process runs on a schedule on the PDC Emulator DC. By default it runs every hour, checking that members of protected groups have the correct ACLs applied to them. Eg. if an attacker creates a malicious ACL entry for a user in the Domain Admins group, unless they modify other AD settings, the SDProp would remove the new rights.

### dsHeuristics
The [dsHeuristics](https://docs.microsoft.com/en-us/windows/win32/adschema/a-dsheuristics) attribute is a string value on the Directory Service object to define multiple forest-wide configuration settings. This can be used to exclude built-in groups from the [Protected Groups](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) list. This means they won't be modified by the *AdminSDHolder* object.

### adminCount
The [adminCount](https://docs.microsoft.com/en-us/windows/win32/adschema/a-admincount) attribute determines whether or not the SDProp process protects a user. `0` means unprotected. Searching for users with this attribute set to `1` means these are likely privileged accounts that could be of special interest.

### Active Directory Users and Computers (ADUC)
ADUC is a GUI console for managing users, groups, computers and contacts in AD. Can also be used through PowerShell.

### ADSI Edit
A GUI tool used to manage objects in AD. It is more powerful and has more access than ADUC has. You can create, modify or delete any object in an AD. It can however, allow changes that could have devastating effects in an AD.

### sIDHistory
[This](https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-sid-history-attribute) attribute holds any SIDs that na object was assigned previously. It is often used when migrating a user across domains to maintain their access. It can be potentially abused to gain elevated access in another domain if SID Filtering isn't enabled.

## NTDS
![[Windows#NTDS]]

## MSBROWSE
MSBROWSE is a Microsoft networking protocol that was used in early Windows-based LANs to provide browsing services. In older windows versions, we could use `nbtstat -A ip-address` to search for the Master browser. If we see `MSBROWSE` then thats the master browser. We could use `mltest` to query the Windows Master Browser for names of Domain Controllers.
> Largely it is obsolete and replace by SMB and CIFS.

## User and Machine Accounts
### Local Accounts
These accounts are stored locally on a specific server or workstation. These accounts' permissions don't work across the domain. The [default accounts](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts) are:
- *Administrator* : first account created on windows installation, SID = `S-1-5-domain-500`. It cannot be deleted or locked, but can be disabled or renamed. Windows 10 and Server 2016 disable this account by default and create a local account in the local administrators group instead.
- *Guest* : disabled by default. Allows anonymous login (*with a blank password*) and limited access rights.
- *SYSTEM* : (or `NT AUTHORITY\SYSTEM`) is the default account used for OS internal functions. It doesn't have a user profile but does have the highest permission level on a Windows host. It isn't a "real user", so it can't be found in User Management or added to groups.
> The `NT AUTHORITY\SYSTEM` has most of the same rights as a regular domain user in an AD environment. If we do gain access to this account on a particular system, we could gather large amounts of data with the read access to the AD environment that could inform potential AD attacks.
- *Network Service* : Predefined local account used by the *Service Control Manager* (*SCM*) for running Windows services. When a service runs as this account, it will present credentials to remote services.
- *Local Service* : Another predefined local account used by the *Service Control Manager* (*SCM*) but has minimal privileges and presents anonymous credentials to the network.

### Domain Users
These users have rights that extend across a domain, granting access to remote resources. Unlike local users, a domain user can log in on any domain-joined host. The different AD account types can be seen [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts). 

The `KRBTGT` account is a very important one as it is the service account for the Key Distribution service and can be used to gain unconstrained access to the domain, escalate privileges and gain domain persistence through attacks like [Golden Ticket](https://attack.mitre.org/techniques/T1558/001/).

### User Naming Attributes
- *UserPrincipalName* (UPN) : The primary logon name for the user, normally the email address of the user.
- *ObjectGUID* : Unique identifier, in AD it remains the same even if the user is removed.
- *SAMAccountName* : A logon name that supports the previous version of Windows clients and servers.
- *objectSID* : The user's Security Identifier (SID). Identifies a user and its group membership during security interactions.
- *sIDHistory* : Previous SIDs for the user object if moved from another domain.

```PowerShell
Get-ADUser -Identity <username>
```

> For a deeper look at user object attributes, check out this [page](https://docs.microsoft.com/en-us/windows/win32/ad/user-object-attributes) 

## Domain-joined vs Non-Domain-joined Machines
### Domain-joined
- Easier access to information sharing within an enterprise
- Central management point (the DC) to get resources, policies and updates from
- Inherits the domain's Group Policy
- Domain users can access the network from any domain-joined host

### Non-Domain-joined / workgroup machines
- Not managed by domain policy
- Complicates resource sharing outside the local network
- Users can make changes to their specific machine
- Accounts are not migrated / accessible from any other hosts within the workgroup

## Active Directory Groups
Groups VS Organisational Units (OUs):
- Groups assign rights and permissions to a set of users
- OUs tend to be for more specific purposes such as allowing a user to reset passwords for others
- OUs are for organising user, groups and resources into logical units for easier overview management

Groups in AD have two fundamental characteristics: *type* and *scope*:
- *Type* : Defines the group's purpose
	- *Security* : Primarily used for ease of assigning permissions and rights to a collection of users
	- *Distribution* : These are mainly for email applications like email lists. This type of group cannot be used to assign permissions to resources in a domain environment.
- *Scope* : Shows how the group can be used within the domain or forest
	- *Domain Local* : Used to manage permissions within a domain. Cannot control resources outside of its domain, but *CAN* have users from other domains in it. *CAN* be nested in other local groups, but *NOT* in global groups.
		- *domain -> universal* : can be done if the domain local group doesn't contain any domain local groups as its members
	- *Global* : Grant access to resources in another domain. Can only contain members from the domain it was created in. Can be nested in other global or local groups.
		- *global -> universal* : can be done if its not a child to another global group
	- *Universal* : Can be used to manage resources across multiple domains, and can give any object within the same forest. *CAN* contain users from any domain. Universial groups are in the Global Catalog (GC) and any changes are replicated across the forest. It is advised to have global groups in the universal group and then just configure users and computers in the global groups, this prevents mass replication and network load when doing activities such as removing a user from a group.
		- *universal -> domain* : no restrictions
		- *universal -> global* : can be converted if it doesn't already contain any universal groups as members

```PowerShell
Get-ADGroup  -Filter * | select samaccountname,groupscope
```

Where groups can be members of other groups, this could accidentally cause unintended privileges for certain users. Tools like [[BloodHound]] are particularly useful in uncovering privileges a user may inherit through one or more nested groups.

**Important Group Attributes**
Like users, group have many [attributes](http://www.selfadsi.org/group-attributes.htm). Some of the most [important group attributes](https://docs.microsoft.com/en-us/windows/win32/ad/group-objects) are:
- *cn* : Common-Name is the name of the group in Active Directory Domain Services (*LDAP*)\
- *member* : Which user, group, and contact objects are members of the group
- *groupType* : Integer that specifies the group type and scope
- *memberOf* : A list of all the groups this group is a member of
- *objectSid* : The [[Windows#Security Identifier (SID)|SID]] of the group

### Default / Built-in Groups
> [default or built-in security groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups)

```PowerShell
Get-ADGroup -Identity "Server Operators" -Properties *
```

| Group Name                           | Description                                                                                                                                                                                                         |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| *Account Operators*                  | Create and modify standard user accounts across a domain, can also log into domain controllers                                                                                                                      |
| *Administrators*                     | Administrator access on a computer or domain (*if this group is on the DC*)                                                                                                                                         |
| *Backup Operators*                   | Can backup and restore all files on a computer. Can log into DCs and are basically Domain Admins. Can also make [[Password Attacks#Dumping Active Directory's NTDS.dit file\|shadow copies of SAM/NTDS databases]]. |
| *DnsAdmins*                          | Access to DNS information. Only created if the DNS server role is/was installed on the DC.                                                                                                                          |
| *Domain Admins*                      | Administrator access on all domain-joined machines.                                                                                                                                                                 |
| *Domain Computers*                   | Any computers in a domain (*aside from DCs*)                                                                                                                                                                        |
| *Domain Controllers*                 | All DCs within a domain.                                                                                                                                                                                            |
| *Domain Guests*                      | Guest accounts within the domain. New accounts are created when signing in as a guest on a domain-joined computer.                                                                                                  |
| *Domain Users*                       | All user accounts within a domain.                                                                                                                                                                                  |
| *Enterprise Admins*                  | Complete configuration access within the domain. Only exists on the root domain in an AD forest. Can make forest-wide changes such as child domains & trusts.                                                       |
| *Event Log Readers*                  | Members can read event logs on local computers. Only created when a host is promoted to a domain controller.                                                                                                        |
| *Group Policy Creator Owners*        | Can manage GPOs in the domain                                                                                                                                                                                       |
| *Hyper-V Administrators*             | Unrestricted access to all features in Hyper-V. If DCs are virtualised, this group becomes effective domain admins.                                                                                                 |
| *IIS_IUSRS*                          | Group used by Internet Information Services (IIS), beginning with IIS 7.0                                                                                                                                           |
| *Pre-Windows 2000 Compatible Access* | Backwards compat for Windows NT 4.0 and earlier. Often a leftover legacy config. Can be used to read information on an AD without an AD login                                                                       |
| *Print Operators*                    | Can manage printers in a domain. Can log into a DC and potentially use a malicious printer driver to escalate privs.                                                                                                |
| *Protected Users*                    | Member of this [group](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#protected-users) have additional protections against credential theft  |
| *Read-only Domain Controllers*       | Contains all Read-only domain controllers in the domain                                                                                                                                                             |
| *Remote Desktop Users*               | Grants permission to use RDP to a host                                                                                                                                                                              |
| *Remote Management Users*            | Grants access to systems via [[WinRM]]                                                                                                                                                                              |
| *Schema Admins*                      | Can modify the [[#Schema\|AD Schema]]. Only exists on the root domain in the AD forest.                                                                                                                             |
| *Server Operators*                   | Only exists on DCs. Members can modify services, access SMB shares and backup files on DCs. No members by default.                                                                                                  |

## Rights and Privileges
- *Rights* are typically for users and groups, they grant access to objects such as files.
- *Privileges* grant a permission to perform an action, such as running a program, shut down a system, reset a password etc. Can be assigned to a user or via a group membership.

> [User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment) : explanation on the different rights a user can be assigned in Windows.

Tools like [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) could let us assign rights to a user we control if we have write access over a GPO. We might want access to privileges such as:
- *SeRemoteInteractiveLogonRight* : Could allow us to RDP to a host
- *SeBackupPrivilege* : Allows a user to create backups, can be used to make copies of Registry hives and the NTDS file.
- *SeDebugPrivilege* : Allows a user to debug and adjust the memory of a process. Can allow tools like [[Mimikatz]] to read memory of the [[Windows#LSASS|LSASS]] service.
- *SeImpersonatePrivilege* : Allows the impersonation of a token of a privileged account such as `NT AUTHORITY\SYSTEM`. Can be used with tools like `JuicyPotato`, `RogueWinRM`, `PrintSpoofer` to esc privs.
- *SeLoadDriverPrivilege* : Can load and unload device drivers, can be used to potentially esc privs
- *SeTakeOwnershipPrivilege* : Allows a user to take ownership of an object. Could be used to gain access to shares or files for example
> Many techniques listed [here](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e) and [here](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html) on windows priv abuse

## View a User's Privileges
```PowerShell
whoami /priv
```

## Configuring Active Directory with PowerShell
This reference https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps is incredibly useful.

## Active Directory Hardening
> More AD best security practices [here](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
### Password Rotation with LAPS
[Microsoft Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is a tools for randomising and rotating local administrator passwords on Windows hosts to prevent lateral movement. LAPS can be configured to rotate a account passwords on a fixed interval. It reduces the impact of a compromised host in an AD environment.

### Audit Policy Settings
Logging and Monitoring are critical for any organisation. Detecting and reacting to unexpected changes or activities means you can respond to potential threats.

### Group Policy Security Settings
GPOs allow you to control the policy settings for specific users, groups, and computers at the OU level. Some important types of security policies are:
- [Account Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-policies) : Manage how user accounts interact with the domain (including passwords, lockouts, and kerberos settings)
- [Local Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-options) : Apply to a specific computer and include host related settings (eg. event audit policy, user rights assignments, specific security settings)
- [Software Restriction Policies](https://docs.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies) : Controls which software can be run on a host
- [Application Control Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control) : Controls which applications can be run by certain users/groups. Tools like [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) can be used to block access to certain types of applications and files (eg. CMD and PowerShell).
- [Advanced Audit Policy Configuration](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/secpol-advanced-security-audit-policy-settings) : Settings to adjust audit activities such as file access, logons, privilege usage etc.

### Update Management (SCCM/WSUS)
The [Windows Server Update Service (WSUS)](https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus) can be installed as a role on a Windows Server and can be used to automatically patch systems. *System Center Configuration Manager* (*SCCM*) is a paid solution that relies on WSUS but offers more features. Patch management is critical to ensure devices are properly protected and none are missed off.

### Group Managed Service Accounts (gMSA)
A gMSA is a privileged account managed by the domain that can be used to run services automatically with credentials. The domain controller manages its password with a 120 char pass. It gets rotated regularly but doesn't ever need to be known by the users.

### Security Groups
Security groups such as [[#Default / Built-in Groups]] offer a important tool for managing access to network resources for a collection of users.

### Account Separation
Administrators must have separate accounts (one regular for day-to-day, and one for administrative actions). This helps to reduce the impact of a user's account being compromised.

### Password Complexity Policies + Pass-phrases + 2FA
Having long, complex passwords is essential (16 chars+ really) and should be enforced through policies. Additionally, having password filters for disallowed passwords containing common words or phrases. MFA is another critical tool that should be used for limiting privileged actions such as RDP access.

### Limiting Domain Admin Account Usage
Domain Admin accounts should only ever really be used to log into Domain Controllers. Logging into other systems could increase the attack vector and chances of the password being compromised in another system.

### Periodically Auditing and Removing Stale Users and Objects
Its important to keep on top of unused accounts and objects. Their security may have fallen behind if they aren't actively used but could still present an attack path.

### Auditing Permissions and Access
Periodic audits of permissions and access should be conducted to ensure users still have the correct privileges for their role and requirements.

### Audit Policies & Logging
Visibility is key in any environment, ensuring that the logging and rules to detect anomalous activities are still effective is key.

### Using Restricted Groups
[Restricted Groups](https://social.technet.microsoft.com/wiki/contents/articles/20402.active-directory-group-policy-restricted-groups.aspx) allow for administrators to configure group membership via Group Policy. It can be used for many things but a key example is controlling the members of the administrator group on each host in the environment.

### Limiting Server Roles
Minimising the number of roles down to only the critical ones on sensitive systems is another way of reducing the attack surface on a machine. Additionally, making sure applications are ideally running in separated server instances (eg. you wouldn't want you web application on the same server as your exchange server or database ideally).

### Limiting Local Admin and RDP Rights
Tightly control which users have local admin rights on which computers. Restricted groups are very useful for this. Limiting the potential for a low privileged account being compromised and then having access to escalate privileges or remote connect to other machines and leak sensitive information.

## Group Policy
Group policy is a Windows feature that provides administrators with a wide array of settings that can be applied to both user and computer accounts in a Windows environment. It can be configured at both a local and domain level.

Group Policy is managed from the *Group Policy Management Console*, custom applications, or using PowerShell [GroupPolicy](https://docs.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2022-ps) module on the domain controller or host.

*If a GPO is compromised, an attacker could gain privileges to move laterally, escalate their privileges, or even full domain compromise.*

**Processing Precedence**:
1. *Local Group Policy* : Defined directly on the host. Overwritten by higher levels.
2. *Site Policy* : Specific to the Enterprise Site a host resides in. Useful for site specific setups (eg. Access Control to certain systems in a certain site).
3. *Domain-wide Policy* : Any settings that you want applied across the entire domain (eg. password policies, desktop wallpapers).
4. *Organisational Unit (OU)* : Affect the users and computers in a specific OU.
5. *OU Policies within other OU's* : Special permissions for specific OUs within a larger OU (eg. Security Analysts within the IT department)

![[Pasted image 20250312083026.png|800]]

> An '*Enforced*' GPO (A setting on a GPO - AKA `No Override`) means that is will NOT be overwritten by later GPOs and instead always enforced.
> If an OU has the *Block Inheritance* option enabled, it will not be subject to the GPOs higher up the chain.

When a GPO is created, it will take a period (*default is every 90 mins +/- 30 min offset for users and computers*) of time to take effect. The random offset is to prevent clients overwhelming the domain controller with Group Policy requests.
> This can be changed in the `Computer Configuration` settings.

If we have access to modify a GPO, we can potentially use this to carry out attacks eg:
- Add additional rights to a compromised user 
- Adding a local administrator
- Scheduling malicious tasks that modify group membership
- Reverse shell connections
- Installing malware throughout a domain

> [[BloodHound]] can be useful for finding these privilege relationships.