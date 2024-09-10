## Windows Versions
The following is a list of the major Windows operating systems and associated version numbers:

| Operating System Names               | Version Number |
| ------------------------------------ | -------------- |
| Windows NT 4                         | 4.0            |
| Windows 2000                         | 5.0            |
| Windows XP                           | 5.1            |
| Windows Server 2003, 2003 R2         | 5.2            |
| Windows Vista, Server 2008           | 6.0            |
| Windows 7, Server 2008 R2            | 6.1            |
| Windows 8, Server 2012               | 6.2            |
| Windows 8.1, Server 2012 R2          | 6.3            |
| Windows 10, Server 2016, Server 2019 | 10.0           |
These can be determined by identifying the `version` field in the `Get-WmiObject -Class wind32_OperatingSystem`
## Useful Powershell Commands
### Manuals
- [Get-WmiObject](https://ss64.com/ps/get-wmiobject.html)
**Get Windows Information**
```powershell
# Get Windows Version
Get-WmiObject -Class win32_OperatingSystem

# Get Process listing
Get-WmiObject -Class win32_Process | select Name,ExecutablePath

# Get Services
Get-WmiObject -Class win32_Service | select Name,StartMode,State,Status

# Get BIOS Information
Get-WmiObject -Class win32_Bios
```

**Get Service Information**
```powershell
# Get the first two (alphabetical) running services
Get-Service | ? {$_.Status -eq "Running"} | select -First 2 | fl
```

**Get Service permissions from registry path**
```powershell
# Get the wuauserv's (windows auth service) permissions via its registry path
Get-ACL -Path HKLM:\System\CurrentControlSet\Services\wuauserv | Format-List
```

**Get Execution Policy**
```powershell
Get-ExecutionPolicy <account>
```
## Useful Commands
### Manuals
- [icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)

| Command                              | Description                                             | Closest Linux Equivalent |
| ------------------------------------ | ------------------------------------------------------- | ------------------------ |
| dir                                  | change directory / list directory                       | cd / ls                  |
| tree                                 | show graphical dir structure                            | ls -R                    |
| icacls                               | show NTFS file permissions for each user in a directory | ls -l                    |
| icacls \<loc> /grant \<user>:\<perm> | grant a user a permission for a file or directory       | chmod                    |
| ipconfig                             | displays IP information                                 | ifconfig                 |
| \<command> /?                        | displays the help page for a command                    | \<command> --help        |

## Connecting to Windows Targets
**Connecting from Windows**
To connect to a windows target from another windows host, you can use the built in RDP (mstsc.exe) application. Profiles can be saved as `.RDP` files, *it is worth looking at these files if discovered in an engagement.*

For this to work, remote access must be [enabled](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access) on the target (disabled by default).

**Connecting from Linux**
`xfreerdp` is a useful tool that can be run from the command line, initiating a RDP session to a windows target. This tool also allows copy pasting and drive redirection for file transfer.

```shell
xfreerdp /v:<targetIp> /u:<username> /p:<password>
```

Other RDP clients such as [Remmina](https://remmina.org/) and [rdesktop](http://www.rdesktop.org/) also exist.

## Boot Partition Directory Structure

| Directory                        | Function                                                                                                                                                                                                                                                                              |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Perflogs                         | Can hold performance logs but is empty by default                                                                                                                                                                                                                                     |
| Program Files                    | On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here.                                                                                                                                                     |
| Program Files (x86)              | 32-bit & 16-bit programs are installed here on 64-bit systems                                                                                                                                                                                                                         |
| ProgramData                      | Hidden folder that contains data for the application, accessible by any app no matter the user                                                                                                                                                                                        |
| Users                            | Contains user profiles for all users that have logged in, contains Public & Default                                                                                                                                                                                                   |
| Default                          | Template directory for a new user profile to be created from                                                                                                                                                                                                                          |
| Public                           | Accessible by all, and shared over the network (must have network auth though)                                                                                                                                                                                                        |
| AppData                          | Per user app data and settings are stored here. <br>**Roaming** contains machine-independent data that should follow the user-profile. <br>**Local** is specific to the local machine and is never network synced.<br>**LocalLow** same a local but has a lower data integrity level. |
| Windows                          | Majority of OS files                                                                                                                                                                                                                                                                  |
| System,<br>System32,<br>SysWOW64 | DLLs for core Windows and Windows API. Windows searches this Dir anytime a program tries to load a DLL without specifying an absolute path.                                                                                                                                           |
| WinSxS                           | Windows Component Store contains a copy of all Windows components, updates, and service packs.                                                                                                                                                                                        |
## File Systems

There are 5 types of file systems in Windows: FAT12, FAT16, FAT32, NTFS, and exFAT. FAT12 & 16 aren't used on modern systems anymore.

*File Allocation Table (FAT)* 32 is used across many storage devices (hard drives, USBs, SD cards etc). 32 means it uses 32-bots to identify data clusters.

**FAT32**
- Pros:
	- Device compatibility - works for most devices
	- OS cross-compat - Windows 95+ and MacOS & Linux support
- Cons:
	- Files less than 4GB
	- No built-in data protection or file compression
	- Must use third-party encryption tools

*New Technology File System (NTFS)* used since Windows NT 3.1. Better supports metadata and performance.

**NTFS**
- Pros:
	- Reliable and can restore after system failure or power loss
	- Provides security through granular permissions (file and folder)
	- Supports very large partitions
	- Has journaling (add, mod, del) built in
- Cons:
	- Most mobiles don't support NTFS natively
	- Older media devices don't support NTFS devices
- Permissions: Inherit from parent folder - `icacls` command
	- Full Control : Read, Write, Modification (change settings), Deletion of files and folders 
	- Modify : Read, Write, Deletion of files and folders
	- List Folder Contents : View and list folders and sub-folders and executing files
	- Read and Execute : View and list files and sub-folders and execute files
	- Write : Add files to folder and write to files
	- Read : View and list folders and sub-folders and view file contents
	- Traverse Folder : Can traverse through folder but cannot view or interact with it
- [icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) command shows each user's permissions in a directory
	- `(CI)`: container inherit
	- `(OI)`: object inherit (dir only), objects in this container inherit this dir's perms
	- `(IO)`: inherit only
	- `(NP)`: do not propagate inherit
	- `(I)`: permission inherited from parent container
	- `F` : full access
	- `D` :  delete access
	- `N` :  no access
	- `M` :  modify access
	- `RX` :  read and execute access
	- `R` :  read-only access
	- `W` :  write-only access

## Users
Users can be created, modified, and deleted in the *Computer Management* application.

## NTFS vs Sharing Permissions
*Server Message Block protocol (SMB)* is used in Windows to connect shared resources (files, printers etc).

Share permission and NTFS permissions are NOT the same, but often resources will have both configured. 

Examining the individual permissions that can be set to grant/secure object access for a network share hosted on a Windows OS running the NTFS file system:
### Share Permissions
- **Full Control** : User may perform all actions given by *Change* and *Read* but can also change permissions for NTFS files and sub-folders.
- **Change** : User can read, edit, delete, and add files and sub-folders.
- **Read** : User can view file & sub-folder contents.

### NTFS Basic Permissions
- **Full Control** : Add, edit, move, delete files and folder, as well as change NTFS permissions on all allowed folders.
- **Modify** : Users are permitted or denied permissions to view or modify files and folders (includes adding & deleting files).
- **Read & Execute** : Users are permitted or denied permissions to read the contents of files and execute programs.
- **List folder contents** : Users are permitted or denied permissions to view a list of files and sub-folders.
- **Read** : Users are permitted or denied permissions to read the contents of files.
- **Write** : Users are permitted or denied permissions to write changes to a file and add new files.
- **Special Permissions** : Advanced permission options (eg. traverse folder, read extended attributes, take ownership)

NTFS permissions apply to the system where the files and folders are hosted. NTFS inheritance also applies. Local (or virtual, RDP) users only need to worry about NTFS permissions, not share permissions.

Share permissions only apply to resources being accessed through SMB, typically a remote system over the network.

NTFS give admins much more granular control over what users can do *within* a folder or file.

### Creating a Network Share
> In most large enterprise environments, shares are created on a Storage Area Network (SAN), Network Attached Storage device (NAS), or a separate partition on drives accessed via a server operating system like Windows Server.
> 
> If a share on a desktop system is discovered, it is either: a small business or a potential beachhead system used by a pen tester or attacker to gather and exfiltrate data.

1. Create a resource
2. Modify the *properties* > *sharing* > *advanced sharing* > enable *share this folder*
3. The *permissions* section is the *access control list (ACL)*, in this case we can consider this the SMB permissions list. 
> Both SMB & NTFS permissions apply to every shared resource in Windows. Typically access control entries (ACEs) are made up of users & groups (aka security principles).
> 
> A server is technically a software function used to server requests from a client. In this case, the tester machine is the client, and the Windows target is our server.
4. By default `Everyone` has `Read` access to a shared resource.
5. We can test this access using `smbclient -L <host> -U <user>` on our tester machine (if this fails to connect, see [Windows Defender Firewall Considerations](#windows-defender-firewall-considerations))
```
$ smbclient -L <Target> -U <user>
Password for [WORKGROUP\<user>]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Shared Data     Disk                <-- This is our custom share we created

```

### Windows Defender Firewall Considerations
Windows Defender Firewall could potentially block access to SMB shares. The firewall blocks access from any device that isn't in the same *workgroup* as the target.

> When a Windows system is part of a workgroup, all `netlogon` requests are authenticated agains the target Window system's SAM database.
> 
> When a Windows system is joined to a Windows Domain environment, all `netlogon` requests are authenticated against `Active Directory`.

Windows Defender Firewall has three default profiles:
- Public
- Private
- Domain

Best practice is to enable predefined rules or add custom exceptions rather than deactivating the firewall altogether. Commonly the firewall is deactivated for sake of convenience. Desktop firewall rules can be centrally managed when joined to a Windows Domain environment through Group Policies.

Using an in-built inbound rule (*File and Printer Sharing (SMB-In)*) and adding the tester machine IP, we can safely enter pass the Defender Firewall via SMB.

### Mounting to a Share
Once a connection is established with a share, we can create a mount point to be able to interact with the file / folder. This is where NTFS permissions apply alongside the SMB permissions.

Under the *properties* > *Security* tab, we can view the NTFS permissions. Grey checkmarks on NTFS permissions were inherited from the parent directory (All permissions by default are inherited).

With the CIFS utility: `sudo apt-get install cifs-utils` we can mount a remote share using SMB:
```
sudo mount -t cifs -o username=<user>,password=<pass> //<ip>/<remote path> <path to local mount>

sudo mount -t cifs -o username=bob,password=ch33s3 //1.2.3.4/"Sensitive Data" /home/attacker/Desktop
```
> You can unmount a share with `sudo umount <path>`

### Monitoring and Tracking in Windows
It is possible to view all shares on a drive in windows with `net share`.

The *C:* drive (or default drive) is shared via SMB at install by default. Meaning anyone with the proper access can access the entire drive of each Windows system on a network!

*Computer Management* is also another tool for monitoring shared resources in Windows. We can poke through the *Shared Folders* tab to view all the shared resources for a system.

Finally, we can utilise *Event Viewer* for logging of access to shared resources. *Windows Logs* > *Security*.

## Windows Services & Processes
### Services
Services are responsible for the creation and management of long-running processes. They can be started at boot and continue to run after a user logs out of the system. Applications can also be deployed as services, eg. network monitoring apps.

Windows services can be managed via the *Service Control Manager (SCM)*, accessible via the `services.msc` MMC add-in. This GUI displays information about each service.

Services can also be queried in PowerShell using `sc.exe` via `Get-Service`.

Services can have several states:
- Running
- Stopped
- Paused
- Starting
- Stopping

They can also have several starting conditions:
- Manually
- Automatically
- Delay at system boot

Windows has three categories of services:
- **Local Services**
- **Network Services**
- **System Services**

Services can usually only be created, modified, and deleted by administrators. 
> Often service misconfigurations are a common privilege escalation vector on Windows.

**Critical System Services**
These [critical system services](https://docs.microsoft.com/en-us/windows/win32/rstmgr/critical-system-services) cannot be stopped or restarted without a system restart. Therefore if any file or resource in use by these services is updated, the system must be restarted.

| Service                   | Description                                                                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| smss.exe                  | Session Manager SubSystem : handles sessions on the system                                                                                                   |
| csrss.exe                 | Client Server Runtime Process : the user-mode portion of the Windows subsystem                                                                               |
| wininit.exe               | Starts the the Wininit.ini file that lists all the changes to be made to Windows when the system restarts after installing a program                         |
| logonui.exe               | Facilitates user login                                                                                                                                       |
| lsass.exe                 | Local Security Authentication Server verifies user logons to the system. Generates the process responsible for authenticating users for the Winlogon service |
| services.exe              | Manages the starting and stopping of services                                                                                                                |
| winlogon.exe              | Handles secure attention sequence, loading user profiles, locking the computer                                                                               |
| System                    | Background service that runs the Windows kernel                                                                                                              |
| svchost.exe with RPCSS    | Manages system services that run from DLLs using the Remote Procedure Call (RPC) Service (RPCSS), eg. Automatic Updates, Windows Firewall.                   |
| svchost.exe with Dcom/PnP | Manages system services that run from DLLs using the Distributed Component Object Model (DCOM) and Plug and Play (PnP) services.                             |
### Processes
Processes run in the background on Windows systems. They run as part of the Windows OS or are started by other installed applications.

Processes associated with applications can often be terminated without severe system impact. Some processes are critical and termination could lead to a loss of functionality, eg. Windows Logon Application, System, Service Host, Windows Session Manager, and Local Security Authority Subsystem Service (LSASS) process.

#### Local Security Authority Subsystem Service (LSASS)
`lsass.exe` is a process responsible for enforcing the security policy on a Windows system. When a user attempts to login, this process verifies their log on and creates appropriate access tokens based on their permissions. LSASS is also responsible for user account password changes. 

All LSASS events are logged to the Windows Security Log.

LSASS is a **high value target** as several tools exist to **extract credentials** in both cleartext and hashed that have been stored in memory by this process.

### Sysinternals Tools
The [SysInternals Tools suite](https://docs.microsoft.com/en-us/sysinternals) is a set of portable Windows applications for administering Windows systems. They can either be downloaded or loaded directly from the internet-accessible file share, eg. `\\live.sysinternals.com\tools\procdump.exe -accepteula`

The suite includes tools such as *Process Explorer*, an enhanced version of *Task Manager*, and *Process Monitor*, all of which can be used to monitor: file system, registry, and network activity of a process.

TCPView can monitor internet activity, and PSExec can manage/connect to remote systems with SMB.

These tools can be used in penetration tests to discover interesting processes and possible privilege escalation paths as well as lateral movement.

### Task Manager
Provides information about running processes, system performance, running services, startup programs, logged-in users/logged in user processes, and services.

Additionally we can also use *Resource Monitor* to view more in-depth performance information.

### Process Explorer
Part of the SysInternal Tools suite, Process Explorer can show which handles and DLLs a process loaded. It shows the parent-child relationship between processes and can be useful for understanding applications and/or troubleshooting issues.

### Service Permissions
Misconfigured service permissions is one of the most overlooked potential threat vectors, giving way to load malicious DLLs, execute applications without an admin account, escalate privileges, and even maintain persistence.

A large issue is that when many of these critical programs are installed, they require a user to run as, a large amount of the time it assumes the user that is installing it (eg. the admin account that is performing the install). This means that critical systems are linked to a specific user, if this account needs to be shut down (eg. the employee leaves that company) then these services will begin to fail. Leading to downtime.

It is highly best practice to use an individual user account to run critical network services (referred to as Service Accounts).

It is also important to not only consider the permissions of the service itself, but also the directory it executes from. This could potentially allow a user to modify the executable or inject malicious DLLs.

### Examining Services
Using the `services.msc` app, it is possible to examine (& configure) the details about a service. The following properties are useful to take note of when targeting a service:
- `Service name` : useful for CLI based tools
- `Path to executable` : displays the path and command used to execute the service
- `Startup type` : can configure when this service starts (could be used to start a malicious service on boot)

If the NTFS permissions of the directory are misconfigured, an attacker could potentially replace the executable of the service or load malicious DLLs.

Under the `Log On` tab, it is possible to see what permission level the service will run as, most services run as `Local System` which is the higher permissions possible (this could be exploitable).

Notable Windows built-in service accounts:
- LocalService
- NetworkService
- LocalSystem

In the `Recovery` tab, failure handling can be configured, one of which is to `run a program`. This could be used to exploit a legitimate service and run a malicious program upon the service failing.

Additionally to the `services.msc` application, the `sc` command can be used to manipulate services. With this tool we can query (`sc qc`), start (`sc start`), stop (`sc stop`), and configure (`sc config`) services.

The `sc sdshow <service>` command will display the [security descriptor](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors) for a given service. All named (and some unnamed) objects is a [securable object](https://docs.microsoft.com/en-us/windows/win32/secauthz/securable-objects) in Windows and therefore is given a security descriptor. This descriptor will identify the object's owner, and primary group containing a *Discretionary Access Control (DACL)* and a *System Access Control List (SACL)*.

> Generally a DACL is used for controlling access to an object. The SACL is used to account for and log access attempts. Both ACLs are displayed in the same way using the Security Descriptor Definition Language (SDDL).

#### Security Descriptor Definition Language (SDDL)
SDDL can look like a complete mess of characters but there is meaning:
```cmd-session
C:\WINDOWS\system32> sc sdshow wuauserv

D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD)
```
Taking a sample:  `D:(A;;CCLCSWRPLORC;;;AU)`

While is is easy to get lost in the seemingly random characters, this string is simply defining the different actions allowed to be performed by a specific group. eg.

`D:(A;;CCLCSWRPLORC;;;AU)`
1. `D:` - the proceeding characters are DACL permissions (SACL would be `S:`)
2. `;;;AU` - defines the security principle is for `Authenticated Users`
3. `A;;` - defines that this list is `Allow`
4. `CC` - SERVICE_QUERY_CONFIG is the full name, and it is a query to the service control manager (SCM) for the service configuration
2. `LC` - SERVICE_QUERY_STATUS is the full name, and it is a query to the service control manager (SCM) for the current status of the service
3. `SW` - SERVICE_ENUMERATE_DEPENDENTS is the full name, and it will enumerate a list of dependent services
4. `RP` - SERVICE_START is the full name, and it will start the service
5. `LO` - SERVICE_INTERROGATE is the full name, and it will query the service for its current status
6. `RC` - READ_CONTROL is the full name, and it will query the security descriptor of the service

If the owner (`O:`) or primary group (`G:`) is set these will in the format: `O: <sid>` or `G: <sid>`.
Each definition is made up of a few key parts:
1. The header - DACL (`D:`) or SACL (`S:`)
2. The *access control entry (ACE)* type - eg. Allow (`A`), Deny (`D`), Audit (`AU`)
3. The [Optional] ACE flags - eg. Container Inherit (`CI`), No propagate (`NP`), Failed access audit (`FA`)
4. The ACE permissions - eg. File Read (`FR`), Delete (`SD`), List Contents (`LC`)
5. The [Optional] object type and/or inherited objet type GUID
6. The trustee - either a SID of a group or user, or an acronym for common SIDs eg. Authenticated Users (`AU`), Local Administrator (`LA`), Everyone (`WD`)

This follows the format:
`<header>(<ACE type>;<Opt - ACE flags>;<ACE permissions>;<Opt - Object type>;<Opt - Inherited object type>;<Trustee>)`

[Full syntax can be found here](https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/)

In PowerShell the `Get-ACL` cmdlet can examine service permissions by targeting the path of a specific service in the registry.
```powershell
Get-ACL -Path HKLM:\System\CurrentControlSet\Services\wuauserv | Format-List
```

This will give both the SDDL & a pretty format too which can be much more readable.

## Windows Sessions
### Interactive
An interactive, or local logon session, is created when a user authenticates to a local or domain system by entering their credentials. An interactive session can be initiated by directly logging in or requesting a secondary logon session through the `runas` command or RDP.

### Non-interactive
These sessions do not require login credentials. There are three types:

| Account                 | Description                                                                                                                                                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Local System Account    | Known as `NT AUTHORITY\SYSTEM`, most powerful account on the system. used for OS-related tasks eg. Windows services. More powerful than administrator user account.                                                            |
| Local Service Account   | Know as `NT AUTHORITY\LocalService`, less privileged version of the SYSTEM account and similar privileges to a local user account. Limited functionality and can start some services.                                          |
| Network Service Account | Known as `NT AUTHORITY\NetworkService`, similar to a standard domain user account. Has similar privileges to the LocalService account on the local machine. Can establish authenticated sessions for certain network services. |

Generally used by Windows OS to automatically start services and applications without user interaction. They have no password associated.

## Windows Security
So many moving parts in Windows can often mean misconfigurations. Windows uses *security principles* for managing authorisation and authentication. Each unit (user, machine, process, or thread) has principles which give permissions to perform or deny certain actions.

### Security Identifier (SID)
Each principle has a unique SID. An SID is used to distinguish units from one another. These SIDs are stored in the security database and added to the user's access token to identify their permissions.

The SID consists of the identifier authority and the relative ID (RID). When using Active Directory, the domain SID is also added to the SID.

```Powershell
PS C:\htb> whoami /user

USER INFORMATION
----------------

User Name           SID
=================== =============================================
ws01\bob S-1-5-21-674899381-4069889467-2080702030-1002
```
The SID follows the pattern:
`S-(Revision Level)-(Identifier authority)-(Sub-authority 1)-(Sub-authority 2)-(etc)`

|**Number**|**Meaning**|**Description**|
|---|---|---|
|S|SID|Identifies the string as a SID.|
|1|Revision Level|To date, this has never changed and has always been `1`.|
|5|Identifier-authority|A 48-bit string that identifies the authority (the computer or network) that created the SID.|
|21|Subauthority1|This is a variable number that identifies the user's relation or group described by the SID to the authority that created it. It tells us in what order this authority created the user's account.|
|674899381-4069889467-2080702030|Subauthority2|Tells us which computer (or domain) created the number|
|1002|Subauthority3|The RID that distinguishes one account from another. Tells us whether this user is a normal user, a guest, an administrator, or part of some other group|
To get the SID of another user, the `wmic useraccount where name='{username}' get name,sid` command (*to be used in command prompt*) can be used. `wmic group ...` can be used for groups too.
### User Account Control (UAC)
A windows security feature to prevent malware from running or manipulating processes. The *Admin Approval Mode* prevents software installations without administrator's knowledge or prevents system-wide changes (This is the admin confirmation popup that appears sometimes). While this prompt is active the execution of the binary (which could be malware) is paused until permission is granted.
![[user-access-control.png]]

### Registry
The registry is a hierarchical database, storing low-level settings for the OS and applications. Divided into computer-specific & user-specific data. The registry editor can be opened with `regedit`.

The 11 possible value types can be found here: [https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)

Each folder under *Computer* is a key. Each root key begins with *HKEY*, keys like *HKEY-LOCAL-MACHINE* are then abbreviated to *HKLM*. This key contains settings that are relevant to the local system. It contains six subkeys: *SAM*, *SECURITY*, *SYSTEM*, *SOFTWARE*, *HARDWARE*, and *BCD* which are all loaded at boot (*HARDWARE* is loaded dynamically).

The entire system registry is stored under: `C:\Windows\System32\Config\`
The user-specific registry (`HKCU`) is stored in the user folder: `C:\Users\<USERNAME>\Ntuser.dat`

### Application Whitelisting
An application whitelist can be implemented to prevent the use of unauthorised applications. A blacklist can be implemented but whitelisting is the recommended approach and requires less maintenance.

**App Locker** is Microsoft's application whitelisting solution. It gives control over which applications and files a user can run. It provides control for executables, scripts, installer files, DLLs, packaged apps, and packed app installers.

It uses a rule based system and can be deployed in audit mode first to test the impact before enforcing the rules.

### Local Group Policy
Group Policy allows administrators to set, configure, and adjust a verity of settings. In a domain environment, group policies are maintained centrally (at a domain controller) and all domain-joined machines (Group Policy objects (GPOs)) will use these settings.

Settings can also be done on an individual machine with Local Group Policies. The Local Group Policy Editor can be opened with `gpedit.msc`. You can then configure `computer configuration` or `user configuration`.

### Windows Defender
Defender includes a cloud-delivered protection in addition to its real-time scanning. This works in-conjunction with automatic sampling of suspicious applications which are uploaded and analysed. The application is "locked" until analysis is complete to prevent any malicious behaviour. Tamper protection also monitors and restricts security settings from being changed through the Registry, Powershell cmdlets, or group policy.

Windows Defender takes advantage of its embedded setting in the OS, allowing it to perform more efficiently than many alternatives whilst still providing effective protections.