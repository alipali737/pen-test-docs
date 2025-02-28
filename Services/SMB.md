```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Server Message Block* (*SMB*) is a client-server protocol for regulating access to shared files, directories, or other resources (printers etc) on a network. 
> Can also be used to communicate between system processes.

Primarily used in windows, but the *Samba* project makes SMB available on Linux and Unix, enabling cross-platform communication via SMB.

Samba can also act as a member or controller for an Active Directory domain.
Each host in a network is part of a *workgroup*, this is used to identify a collection of computers and their resources on an SMB network.

**Standard Port:** 
- NBT(NetBIOS) : *139*/tcp & *137-138*/udp
- CIFS/SMB : *445*/tcp
> On a windows system SMB can run directly over port 445/tcp without needing NetBIOS.
> If a non-windows system (eg. SAMBA service) or NetBIOS is enabled, SMB will run over port 139/tcp with NetBIOS.


**Version Names:** 

| service name | releases link | notes                 |
| ------------ | ------------- | --------------------- |
| Samba        |               | */etc/samba/smb.conf* |
| Microsoft-ds |               |                       |
## How it works
A client must establish a connection with an SMB server application before any access can be provided, this is done with a TCP handshake.

An SMB server can then provide arbitrary parts of its local file system as shares. *Access Control Lists* (*ACLs*) are used to control the shares (Not the underlying file permissions, that is [[Windows#NTFS vs Sharing Permissions|NTFS]]).
#### Samba
Samba is for non-windows systems. Samba implements the *Common Internet File System* (*CIFS*) protocol. It is a specific implementation of the SMB protocol (like a dialect), created by Microsoft. It allows connections with newer Windows systems.

When passing SMB commands over Samba to an older NetBIOS service, it usually connects over TCP ports *137-139*, but CIFS only uses *445*.

The Samba SMB service controls two daemons (*smbd* & *nmbd* for NetBIOS message block).

Each host reserves a name, or is given one by the *NetBIOS Name Server* (*NBNS*) or *Windows Internet Name Service* (*WINS*).

The Samba SMB daemon can be restarted with `systemctl`
## Potential Capabilities
- Some configuration settings can give dangerous behaviours:

| **Setting**                 | **Description**                                                     |
| --------------------------- | ------------------------------------------------------------------- |
| `browseable = yes`          | Allow listing available shares in the current share?                |
| `read only = no`            | Forbid the creation and modification of files?                      |
| `writable = yes`            | Allow users to create and modify files?                             |
| `guest ok = yes`            | Allow connecting to the service without using a password?           |
| `enable privileges = yes`   | Honor privileges assigned to specific SID?                          |
| `create mask = 0777`        | What permissions must be assigned to the newly created files?       |
| `directory mask = 0777`     | What permissions must be assigned to the newly created directories? |
| `logon script = script.sh`  | What script needs to be executed on the user's login?               |
| `magic script = script.sh`  | Which script should be executed when the script gets closed?        |
| `magic output = script.out` | Where the output of the magic script needs to be stored?            |
- Access shared resources or files on a network.
- Gain insights as to the devices and potential users on a network.
- Extracting hashes from the SAM database : [[CrackMapExec#Extracting Hashes from SAM Database]]
- [[Password Attacks#Pass the Hash with CrackMapExec|Pass the Hash]]
- Forced Authentication Attacks using [[Responder]]

## MSRPC / RPCclient
RPC lets us execute a procedure (eg. a function) in a local or remote process. We can use `MS-RPCE` which is RPC over SMB (using SMB named pipes). As we can only gain limited information from tools like `nmap` for SMB services, we can use `RPCclient` to manually inspect the service.

```bash
# Authenicate with Null session (anonymous user)
rpcclient -U "" [Target]

Enter WORKGROUP\'s password:
rpcclient $> 
```

| **Query**                 | **Description**                                                    |
| ------------------------- | ------------------------------------------------------------------ |
| `srvinfo`                 | Server information.                                                |
| `enumdomains`             | Enumerate all domains that are deployed in the network.            |
| `querydominfo`            | Provides domain, server, and user information of deployed domains. |
| `netshareenumall`         | Enumerates all available shares.                                   |
| `netsharegetinfo <share>` | Provides information about a specific share.                       |
| `enumdomusers`            | Enumerates all domain users.                                       |
| `queryuser <RID>`         | Provides information about a specific user.                        |
We can run an enumeration attack like:
```bash
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
which will use RPC to query for users by enumerating through RIDs. This can also be done with tools like [samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py).

Additionally, the [SMBMap](https://github.com/ShawnDEvans/smbmap) and [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) tools are also widely used and helpful for the enumeration of SMB services.
```bash
smbmap -H [Target]

crackmapexec smb [Target] --shares -u '' -p ''
```

Finally [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) can also be used to gather a range of different information
```bash
./enum4linux-ng.py [Target] -A
```

## Interacting with a share
### Windows
You can use the run tool (`[WINKEY]+[R]`) and input the address as `\\<HOST>\<SHARE>\`.
```
C:\> net use n: \\<HOST>\<SHARE>
C:\> net use n: \\<HOST>\<SHARE> /user:<user> <pass>

# Scan a drive for the number of files on it
C:\> dir n: /a-d /s /b | find /c ":\"

# Search for a pattern in file names
C:\> dir n:\*pass* /s /b

# Search for a pattern in text-based files
C:\> findstr /s /i pass n:\*.*
```
> More findstr examples [here](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr#examples)
```PowerShell
# Equivalent of the 'dir' / 'ls' commands to list a directory (alias 'gci')
PS C:\> Get-ChildItem \\<HOST>\<SHARE>

# Mount a new drive
PS C:\> New-PSDrive -Name "N" -Root "\\<HOST>\<SHARE>" -PSProvider "FileSystem"

# Authentication
PS C:\> $username = '<user>'
PS C:\> $password = '<pass>'
PS C:\> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\> New-PSDrive -Name "N" -Root "\\<HOST>\<SHARE>" -PSProvider "FileSystem" -Credential $cred

# Count the items on a share
PS C:\> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

# Search for a pattern in a path
PS C:\> Get-ChildItem -Recurse -Path N:\ -Include *pass* -File

# Search for a pattern in files
PS C:\> Get-ChildItem -Recurse -Path N:\ | Select-String "pass" -List
```

### Linux
```bash
# Mount a share
$ sudo mkdir /mnt/<Share>
$ sudo mount -t cifs -o username=<user>,password=<pass>,domain=. //<HOST>/<SHARE> /mnt/<SHARE>

# Using a credential file (same format as above but in a file)
$ sudo mount -t cifs //<HOST>/<SHARE> /mnt/<SHARE> -o credentials=<credentials_file>
# == credentials.txt ==
# username=<user>
# password=<pass>
# domain=.
# =====================
```
> To use `cifs` we need to install `cifs-utils` --> `sudo apt install cifs-utils`

```bash
# Search for pattern in path
$ find /mnt/<SHARE> -name *pass*

# Search for pattern in files
$ grep -rn /mnt/<SHARE> -ie pass
```

## PsExec and Alternative Tools
Executing code remotely is incredibly powerful, tools like [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) can do this.

[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) contains a Windows service image inside of its executable. It deploys the service to the admin$ (*by default*) share on the remote machine. It then uses the DCE/RPC interface over SMB to access the Windows Service Control Manager API. Then it starts the PSExec service on the remote machine. This service creates a named pipe that can send commands to the system.

**Alternatives**
- [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Python PsExec like functionality example using [RemComSvc](https://github.com/kavika13/RemCom).
- [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - A similar approach to PsExec without using [RemComSvc](https://github.com/kavika13/RemCom). The technique is described here. This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is *useful when the target machine does NOT have a writeable share* available.
- [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) - This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - includes an implementation of `smbexec` and `atexec`.
- [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) - Ruby PsExec implementation.

## Enumeration Checklist
> Useful SANS cheatsheet: https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf

| Goal                      | Command(s)                                                                                                                                                                                         | Refs                                                                   |     |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | --- |
| Version Identification    | ./smbver.sh [target]<br><br>smbclient -L [target]                                                                                                                                                  |                                                                        |     |
| Enumerate Hostname        | nmblookup -A [target]                                                                                                                                                                              |                                                                        |     |
| List shares               | smbmap -H [target]<br>smbmap -H [target] -r [dir]<br><br>smbclient -L<br><br>nmap -v -p 445 --script=smb-enum-shares.nse --script-args=unsafe=1 [target]<br><br>![[CrackMapExec#List SMB Shares]]  |                                                                        |     |
| Download & upload Files   | smbmap -H [target] --download [remote_path]<br>smbmap -H [target] --upload [local_path] \[remote_path]                                                                                             |                                                                        |     |
| Check Null Sessions       | smbclient //MOUNT/share -l target -N<br><br>smbmap -H [target]<br><br>rpcclient -U "" -N [target]<br><br>smbclient -U [user] \\\\\\\\[target]\\\\[share name]                                      |                                                                        |     |
| Performing RCE            | impacket-psexec [user]:'[pass]'@[target]<br>impacket-smbexec<br>impacket-atexec<br><br>crackmapexec smb [target] -u [user] -p '[pass]' -x '[cmd]' --exec-method smbexec                            | <br><br><br><br>the `--exec-method` is optional (defaults to `atexec`) |     |
| SMB Bruteforce            | hydra -L [user_list] -P [pass_list] smb://[ip]                                                                                                                                                     | [[Hydra]]                                                              |     |
| Check for vulns           | nmap scripts : smb-vuln* --script-args=unsafe=1                                                                                                                                                    |                                                                        |     |
| Overall Scan              | enum4linux -a [target]<br>enum4linux-ng -A [target]                                                                                                                                                |                                                                        |     |
| Groups via SMB            | nmap --script=smb-enum-group                                                                                                                                                                       |                                                                        |     |
| Logged in users via SMB   | nmap -sU -sS --script=smb-enum-sessions [target] -vvvvv<br><br>nmap -p[Port] --script=smb-enum-sessions [target] -vvvvv<br><br>crackmapexec smb [target(s)] -u [user] -p '[pass]' --loggedon-users |                                                                        |     |
| Password policies via SMB | nmap -p[port] --script=smb-enum-domains [target] -vvvvv                                                                                                                                            |                                                                        |     |
| OS discovery              | nmap [target] --script=smb-os-discovery.nse                                                                                                                                                        |                                                                        |     |
