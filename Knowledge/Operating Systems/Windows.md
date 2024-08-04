---
layout: page
title: Windows
parent: Operating Systems
grand_parent: Knowledge
---
# {{ page.title }}
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---
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

## Useful Commands
### Manuals
- [icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)

| Command                              | Description                                             | Closest Linux Equivalent |
| ------------------------------------ | ------------------------------------------------------- | ------------------------ |
| dir                                  | change directory / list directory                       | cd / ls                  |
| tree                                 | show graphical dir structure                            | ls -R                    |
| icacls                               | show NTFS file permissions for each user in a directory | ls -l                    |
| icacls \<loc> /grant \<user>:\<perm> | grant a user a permission for a file or directory       | chmod                    |

## Connecting to Windows Targets
**Connecting from Windows**
To connect to a windows target from another windows host, you can use the built in RDP (mstsc.exe) application. Profiles can be saved as `.RDP` files, *it is worth looking at these files if discovered in an engagement.*

For this to work, remote access must be [enabled](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access) on the target (disabled by default).

**Connecting from Linux**
`xfreerdp` is a useful tool that can be run from the command line, initiating a RDP session to a windows target. This tool also allows copy pasting and drive redirection for file transfer.

```shell-session
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