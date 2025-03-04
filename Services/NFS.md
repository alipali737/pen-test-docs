```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Network File System* (*NFS*) is a network file system that has the same purpose as [[SMB & RPC]]. NFS is used within Linux and Unix systems. NFS clients *cannot* communicate directly with SMB servers.

**Standard Port:** 
- *NFSv4* : 2049/(udp or tcp)
- *ONC-RPC* : 111/(udp or tcp)

**Version Names:** 

| service name | releases link                                             | notes                                                                                                                                                                                |
| ------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| NFSv2        |                                                           | Older but still supported, initially used UDP exclusively                                                                                                                            |
| NFSv3        |                                                           | More features (variable file size, better error reporting etc) but doesn't work with NFSv2 clients. Also authenticates the client computer itself.                                   |
| NFSv4        | [RFC 8881](https://datatracker.ietf.org/doc/html/rfc8881) | Includes Kerberos, works through firewalls and on the internet, no longer requires port-mappers, supports ACLs, uses stateful protocol. Requires clients to authenticate themselves. |
## How it works
- Based on [Open Network Computing Remote Procedure Call](https://en.wikipedia.org/wiki/Sun_RPC) (ONC-RPC / SUN-RPC) which used *TCP* & *UDP* ports *111* using *XDR* format.
- NFS uses the RPC protocol's options for its authentication and authorisation, it has no components itself. Often it uses the UNIX *UID*/*GID* and *group memberships* for authentication. (This method should only be used in trusted networks as the client & server don't have to have the same UID/GID mappings which could introduce an attack vector).

## Configuration
Configured via the */etc/exports* file which is a table of physical filesystems on an NFS server:
```bash
cat /etc/exports 

# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
/srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
/srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
/srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
```

Format: *{ directory_path } { ...hostname/subnet(permissions) }*
[Exports file manual](https://linux.die.net/man/5/exports)
### Permissions
- *rw* : read and write
- *ro* : read only
- *sync* : synchronous data transfer (slower)
- *async* : asynchronous data transfer (faster)
- *secure* : ports above 1024 won't be used
- *insecure* : ports over 1024 will be used
- *no_subtree_check* : disables checking of subdirectory trees
- *root_squash* : prevents `root` from accessing files by changing all UID/GID 0 to `anonymous`
- *nohide* : by default if you export two resources and one is also mounted under the other, it will hide the resource unless both are mounted. This option prevents this and an authorised user can freely move between the two resources.
### Example
```bash
$ echo '/mnt/nfs 10.0.9.0/24(rw,sync,secure,root_squash)' >> /etc/exports
$ systemctl restart nfs-kernel-server
$ exportfs

/mnt/nfs    10.0.9.0/24
```

## Potential Capabilities
- Access to sensitive information if located in a file share
- File transfer via RPC
- Create usernames & group names on the local system to gain access to NFS files (Priv Esc)
- Upload a shell to escalate privileges
	- If we have SSH access and we want to read files from another folder, we can upload a shell to the NFS share that has the SUID of the target user and run it via our SSH user.

## Enumeration Checklist

| Goal                                    | Command(s)                                                                                          | Refs |
| --------------------------------------- | --------------------------------------------------------------------------------------------------- | ---- |
| Check service ports for service running | sudo nmap [target] -p111,2049 -sV --script nfs*                                                     |      |
| Check for mountable NFS shares          | nmap [target] -sV --script=nfs-showmount<br><br>showmount -e [target]                               |      |
| Mount a share                           | mkdir target-NFS<br>sudo mount -t nfs [target]:/ ./target-NFS/ -o nolock<br>cd target-NFS<br>tree . |      |
### Nmap Scripts
- `nfs*`
- `rpcinfo` : list all currently running RPC services
- `nfs-showmount` : shows mounts available
- `nfs-statfs` : show stats of mounts