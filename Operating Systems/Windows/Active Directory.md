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
Get-ADGroup  -Filter * |select samaccountname,groupscope
```

Where groups can be members of other groups, this could accidentally cause unintended privileges for certain users. Tools like [[BloodHound]] are particularly useful in uncovering privileges a user may inherit through one or more nested groups.