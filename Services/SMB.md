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
- SMB : *137-139*/tcp
- CIFS : *445*/tcp

**Version Names:** 

| service name | releases link | notes                 |
| ------------ | ------------- | --------------------- |
| Samba        |               | */etc/samba/smb.conf* |
| Microsoft-ds |               |                       |
## How it works
A client must establish a connection with an SMB server application before any access can be provided, this is done with a TCP handshake.

An SMB server can then provide arbitrary parts of its local file system as shares. *Access Control Lists* (*ACLs*) are used to control the shares (Not the underlying file permissions, that is [[Windows#NTFS vs Sharing Permissions|NTFS]]).
#### Samba
Samba implements the *Common Internet File System* (*CIFS*) protocol. It is a specific implementation of the SMB protocol (like a dialect), created by Microsoft. It allows connections with newer Windows systems.

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

## RPCclient
As we can only gain limited information from tools like `nmap` for SMB services, we can use `RPCclient` to manually inspect the service.

```shell
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
```shell
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
which will use RPC to query for users by enumerating through RIDs. This can also be done with tools like [samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py).

Additionally, the [SMBMap](https://github.com/ShawnDEvans/smbmap) and [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) tools are also widely used and helpful for the enumeration of SMB services.
```shell
smbmap -H [Target]

crackmapexec smb [Target] --shares -u '' -p ''
```

Finally [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) can also be used to gather a range of different information
```shell
./enum4linux-ng.py [Target] -A
```
## Enumeration Checklist

| Goal                      | Command(s)                                                                                                                                                         | Refs      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------- |
| Version Identification    | ./smbver.sh [target]<br><br>smbclient -L [target]                                                                                                                  |           |
| Enumerate Hostname        | nmblookup -A [target]                                                                                                                                              |           |
| List shares               | smbmap -H [target]<br><br>smbclient -L<br><br>nmap -v -p 445 --script=smb-enum-shares.nse --script-args=unsafe=1 [target]<br><br>![[CrackMapExec#List SMB Shares]] |           |
| Check Null Sessions       | smbclient //MOUNT/share -l target -N<br><br>smbmap -H [target]<br><br>rpcclient -U "" -N [target]<br><br>smbclient -U [user] \\\\\\\\[target]\\\\[share name]      |           |
| SMB Bruteforce            | hydra -L [user_list] -P [pass_list] smb://[ip]                                                                                                                     | [[Hydra]] |
| Check for vulns           | nmap scripts : smb-vuln* --script-args=unsafe=1                                                                                                                    |           |
| Overall Scan              | enum4linux -a [target]<br>enum4linux-ng -A [target]                                                                                                                |           |
| Groups via SMB            | nmap --script=smb-enum-group                                                                                                                                       |           |
| Logged in users via SMB   | nmap -sU -sS --script=smb-enum-sessions [target] -vvvvv<br><br>nmap -p[Port] --script=smb-enum-sessions [target] -vvvvv                                            |           |
| Password policies via SMB | nmap -p[port] --script=smb-enum-domains [target] -vvvvv                                                                                                            |           |
| OS discovery              | nmap [target] --script=smb-os-discovery.nse                                                                                                                        |           |
