```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

**5 Core Principles**
- Everything is a file
- Small, single-purpose utilities
- Chain together programs for complex tasks
- Avoid captive user interfaces (Most users use the shell)
- Config is stored in text files (eg. `/etc/passwd`)

**4 Layers**
1. Hardware - Physical resources
2. Kernel - Core of the Linux OS, controls the system's resources
3. Shell - Commands to execute the kernel's functions
4. System utilities - Makes OS functions available to the user
## Glossary
| Term            | Description                                                                                                                              |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Bootloader      | Code that guide the booting of the OS                                                                                                    |
| OS Kernel       | Central component that manages the system's I/O devices at a hardware level                                                              |
| Daemons         | Background services that handle key functions like scheduling (these tend to have a `d` after the name eg. `ssh service is called sshd`) |
| Graphics server | Graphical sub-system (server) called 'X' or 'X-server' that handles the execution of graphical programs                                  |
| STDIN - 0       | Data stream for input                                                                                                                    |
| STDOUT - 1      | Data stream for output                                                                                                                   |
| STDERR - 2      | Data stream for error output                                                                                                             |
### Directories
| Path   | Description                                                                               |
| ------ | ----------------------------------------------------------------------------------------- |
| /      | Top level directory - contains all files required for boot                                |
| /bin   | Essential command binaries                                                                |
| /boot  | Static bootloader, kernel executables, and files required to boot the OS                  |
| /dev   | Device files for accessing hardware devices                                               |
| /etc   | Local system config files (& sometimes app config files)                                  |
| /home  | Each user's subdirectory storage                                                          |
| /lib   | Shared libraries for system boot                                                          |
| /media | External storage devices are mounted here                                                 |
| /mnt   | Temporary mount point for regular filesystems                                             |
| /opt   | Optional files such as third-party tools                                                  |
| /root  | Home dir for root user                                                                    |
| /sbin  | System admin executables                                                                  |
| /tmp   | Temporary storage                                                                         |
| /usr   | Contains executables, libraries, man files, etc                                           |
| /var   | Contains variable data files such as logs, email in-boxes, web app files, cron files, etc |
## Command Cheatsheet
|**Command**|**Description**|
|---|---|
|`man <tool>`|Opens man pages for the specified tool.|
|`<tool> -h`|Prints the help page of the tool.|
|`apropos <keyword>`|Searches through man pages' descriptions for instances of a given keyword.|
|`cat`|Concatenate and print files.|
|`whoami`|Displays current username.|
|`id`|Returns users identity.|
|`hostname`|Sets or prints the name of the current host system.|
|`uname`|Prints operating system name.|
|`pwd`|Returns working directory name.|
|`ifconfig`|The `ifconfig` utility is used to assign or view an address to a network interface and/or configure network interface parameters.|
|`ip`|Ip is a utility to show or manipulate routing, network devices, interfaces, and tunnels.|
|`netstat`|Shows network status.|
|`ss`|Another utility to investigate sockets.|
|`ps`|Shows process status.|
|`who`|Displays who is logged in.|
|`env`|Prints environment or sets and executes a command.|
|`lsblk`|Lists block devices.|
|`lsusb`|Lists USB devices.|
|`lsof`|Lists opened files.|
|`lspci`|Lists PCI devices.|
|`sudo`|Execute command as a different user.|
|`su`|The `su` utility requests appropriate user credentials via PAM and switches to that user ID (the default user is the superuser). A shell is then executed.|
|`useradd`|Creates a new user or update default new user information.|
|`userdel`|Deletes a user account and related files.|
|`usermod`|Modifies a user account.|
|`addgroup`|Adds a group to the system.|
|`delgroup`|Removes a group from the system.|
|`passwd`|Changes user password.|
|`dpkg`|Install, remove and configure Debian-based packages.|
|`apt`|High-level package management command-line utility.|
|`aptitude`|Alternative to `apt`.|
|`snap`|Install, remove and configure snap packages.|
|`gem`|Standard package manager for Ruby.|
|`pip`|Standard package manager for Python.|
|`git`|Revision control system command-line utility.|
|`systemctl`|Command-line based service and systemd control manager.|
|`ps`|Prints a snapshot of the current processes.|
|`journalctl`|Query the systemd journal.|
|`kill`|Sends a signal to a process.|
|`bg`|Puts a process into background.|
|`jobs`|Lists all processes that are running in the background.|
|`fg`|Puts a process into the foreground.|
|`curl`|Command-line utility to transfer data from or to a server.|
|`wget`|An alternative to `curl` that downloads files from FTP or HTTP(s) server.|
|`python3 -m http.server`|Starts a Python3 web server on TCP port 8000.|
|`ls`|Lists directory contents.|
|`cd`|Changes the directory.|
|`clear`|Clears the terminal.|
|`touch`|Creates an empty file.|
|`mkdir`|Creates a directory.|
|`tree`|Lists the contents of a directory recursively.|
|`mv`|Move or rename files or directories.|
|`cp`|Copy files or directories.|
|`nano`|Terminal based text editor.|
|`which`|Returns the path to a file or link.|
|`find`|Searches for files in a directory hierarchy.|
|`updatedb`|Updates the locale database for existing contents on the system.|
|`locate`|Uses the locale database to find contents on the system.|
|`more`|Pager that is used to read STDOUT or files.|
|`less`|An alternative to `more` with more features.|
|`head`|Prints the first ten lines of STDOUT or a file.|
|`tail`|Prints the last ten lines of STDOUT or a file.|
|`sort`|Sorts the contents of STDOUT or a file.|
|`grep`|Searches for specific results that contain given patterns.|
|`cut`|Removes sections from each line of files.|
|`tr`|Replaces certain characters.|
|`column`|Command-line based utility that formats its input into multiple columns.|
|`awk`|Pattern scanning and processing language.|
|`sed`|A stream editor for filtering and transforming text.|
|`wc`|Prints newline, word, and byte counts for a given input.|
|`chmod`|Changes permission of a file or directory.|
|`chown`|Changes the owner and group of a file or directory.|
## Networks
### Network Access Control
**Discretionary Access Control (DAC)**
- Utilises Owners, Groups, Users to provide permissions
- Reading, Writing, Execution, Deletion
- Examples: Linux filesystem

**Mandatory Access Control (MAC)**
- Each resource is given a security level
- Each user is given a security clearance
- User must have greater or equal clearance to the security level
- Examples: Military, government, financial, and healthcare systems (high-security systems)

**Role-Based Access Control (RBAC)**
- Users are assigned roles based on some criteria
- Each role has a level of permissions (eg. read, write, admin)
- Large environments that scale and need flexibility
- Examples: Discord roles, Github teams/roles

### Troubleshooting
1. Ping - connection testing
2. Traceroute - traffic path tracing
3. Netstat - network connections and ports
4. Tcpdump - 
5. Wireshark - traffic monitoring
6. Nmap - network mapping

### Common Network Issues
- Network connectivity issues
- DNS resolution issues
- Packet loss
- Network performance issues

### Common Network Issue Causes
- Misconfigured firewalls or routers
- Damaged network cables or connectors
- Incorrect network settings
- Hardware failure
- Incorrect DNS server settings
- DNS server failure
- Misconfigured DNS records
- Network congestion
- Outdated network hardware
- Incorrectly configured network settings
- Unpatched software or firmware
- Lack of proper security controls

### Hardening
**SELinux**
- A *MAC* system built into the kernel, enforcing a policy that defines AC for each process and file.

**AppArmor**
- Also a *MAC* system but implements the *Linux Security Module (LSM)*, using app profiles to define access to other resources.
- Easier to configure than SELinux but less fine-grain control.

**TCP Wrappers**
- Host-based Network Access Control.
- Restrict access to network services & systems based on the client IP.
- `/etc/hosts.allow` & `/etc/hosts.deny` which define which services and hosts can access the system by their IPs.
```
[/etc/hosts.allow]
# Allows SSH from local network
sshd : 10.129.14.0/24

# Allow access to FTP from a specific host
ftpd : 10.129.14.10

# Allow access to Telnet from any host in the inlanefreight.local domain
telnetd : .inlanefreight.local

[/etc/hosts.deny]
# Deny access to all services from any host in the inlanefreight.com domain
ALL : .inlanefreight.com

# Deny access to SSH from a specific host
sshd : 10.129.22.22

# Deny access to FTP from hosts with IP addresses in the range of 10.129.22.0 to 10.129.22.255
ftpd : 10.129.22.0/24
```
#### Challenges
##### SELinux
- Install SELinux on your VM
	- `sudo apt-get install selinux-basics selinux-policy-default auditd` 
- Configure SELinux to prevent a user from accessing a specific file. 
- Configure SELinux to allow a single user to access a specific network service but deny access to all others.                                                                 
- Configure SELinux to deny access to a specific user or group for a specific network service.
##### AppArmor
- Configure AppArmor to prevent a user from accessing a specific file.
- Configure AppArmor to allow a single user to access a specific network service but deny access to all others.
- Configure AppArmor to deny access to a specific user or group for a specific network service.
##### TCP Wrappers
- Configure TCP wrappers to allow access to a specific network service from a specific IP address
- Configure TCP wrappers to deny access to a specific network service from a specific IP address.
- Configure TCP wrappers to allow access to a specific network service from a range of IP addresses.

### Remote Desktop Protocols
**XServer (X11)**
- Unencrypted (Can be tunnelled through SSH for security)
- Primarily uses TCP/IP on ports TCP/6001-6009
- Graphical output is rendered on the local computer - saves traffic & load on remote system.
- Unencrypted X11 traffic can be realised with tools like `xwd` and `xgrabsc`

**X Display Manager Control Protocol (XDMCP)**
- Uses UDP on port 177 between X terminals and computers under Unix/Linux
- Insecure and susceptible to a MitM attack

**Virtual Network Computing (VNC)**
- Most common for RDP tools
	- `RealVNC`
	- `UltraVNC`
- Utilises encryption, and authentication before access
- Also supports screen sharing for collaboration
- Either the actual screen and inputs are provided OR a virtual login session is created
- Usually it the VNC server listens on TCP/5900 increasing by 1 for each display (eg. 5902 is third display)

## Securing Linux Systems
- `apt update && apt dist-upgrade` OS and packages
- Utilise the linux firewall and/or `iptables` to manage traffic flow
- If SSH enabled:
	- Disable password login
	- Disable root login
	- Utilise `fail2ban` to handle failed login attempts
- Manage access controls
	- Use `sudoers` config to run commands as root where needed
- Regular security audits
- Lock down the system with SELinux or AppArmor
- Additional config
	- Remove or disable unnecessary services and software
	- Remove all services that use unencrypted authentication mechanisms
	- Ensure NTP (Keeps system time accurate) is enabled and Syslog (logs system information) is running
	- Each user has their own account
	- Enforce strong passwords
	- Password aging and prevent previous passwords
	- Lock accounts after auth failures
	- Disable all unwanted SUID/SGID binaries (Permissions to take temporary user/group ownership of the file)

### The powershell for linux blind-spot
Similar to the issues in [[Windows#Windows Subsystem for Linux]], PowerShell Core can be installed on Linux systems and carry over many normal PowerShell functions. This two concepts of installing a form of the 'opposite' OS on a system often creates a sneaky blind-spot and potential for attack vectors (little knowledge is known on the potential attack vectors yet). Attacks via these systems have been seen to avoid AV and EDR mechanisms.

### Firewall Setup
- `iptables` is a utility for configuring firewall rules
- Typically the linux firewall is implemented using the *Netfilter* framework (part of the kernel)
	- Provides hooks to intercept & modify traffic
#### Iptables
- Alternative tools
	- `Nftables` : modern syntax & better performance, but isn't compatible with iptables' rules
	- `UFW` : user-friendly interface, built on-top of `iptables`
	- `FirewallD` : dynamic & flexible for managing complex firewall configs. Large set of rules & can create custom firewall zones and services.
- Primary components
	- **Tables** : Organise and categorise firewall rules
	- **Chains** : Group firewall rules applied to a specific type of traffic
	- **Rules** : Define criteria for filtering traffic and the actions to be taken upon matches
	- **Matches** : Used to match specific criteria for filtering traffic (eg. source or destination IP)
	- **Targets** : The actions for packets that match a specific rule (eg. accept, drop)

##### Tables

| Table Name | Description                                                          | Built-in Chains                                 |
| ---------- | -------------------------------------------------------------------- | ----------------------------------------------- |
| `filter`   | Used to filter network traffic on IP addresses, ports, and protocols | INPUT, OUTPUT, FORWARD                          |
| `nat`      | Used to modify the source or destination IP of packets               | PREROUTING, POSTROUTING                         |
| `mangle`   | Used to modify the header fields of packets                          | PREROUTING, OUTPUT, INPUT, FORWARD, POSTROUTING |
| `raw`      | Special packet processing                                            | PREROUTING, OUTPUT                              |
##### Chains
Two types of chains:
- Built-in chains - automatically created when a table is created (eg. INPUT)
	- `INPUT` configures incoming traffic
	- `OUTPUT` configures outgoing traffic
	- `FORWARD` configures traffic being forwarded elsewhere
	- `PREROUTING` modify the destination IP of incoming packets before the routing table processes them
	- `POSTROUTING` modifies the source IP of outgoing packets after the router has processed them
- User-defined chains - used to group similar rules (eg. if you had multiple web servers with similar rules)

##### Rules and Targets
A rule consists of a set of criteria or matches and an action (target) for the packets that match.
The criteria or matches looks for matches in the IP header (eg. IP addresses, protocols, ports), then the target specifies how to process that packet (eg. drop, reject, accept, modify).

**Common Targets:**


| Target Name  | Description                                                                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ACCEPT`     | Allows the packet to pass through the firewall and continue to its destination                                                                              |
| `DROP`       | Drops the packet, effectively blocking it from passing through the firewall                                                                                 |
| `REJECT`     | Drops the packet and sends an error message back to the source address, notifying them that the packet was blocked                                          |
| `LOG`        | Logs the packet information to the system log                                                                                                               |
| `SNAT`       | Modifies the source IP address of the packet, typically used for Network Address Translation (NAT) to translate private IP addresses to public IP addresses |
| `DNAT`       | Modifies the destination IP address of the packet, typically used for NAT to forward traffic from one IP address to another                                 |
| `MASQUERADE` | Similar to SNAT but used when the source IP address is not fixed, such as in a dynamic IP address scenario                                                  |
| `REDIRECT`   | Redirects packets to another port or IP address                                                                                                             |
| `MARK`       | Adds or modifies the Netfilter mark value of the packet, which can be used for advanced routing or other purposes                                           |
**Example:** Create a new rule in the `INPUT` chain that filters incoming TCP packets destined for port 22 (SSH) and accepts them
```shell
$ sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

##### Matches
Matches are used to match specific characteristics of a packet:

| **Match Name**          | **Description**                                                    |
| ----------------------- | ------------------------------------------------------------------ |
| `-p` or `--protocol`    | Specifies the protocol to match (e.g. tcp, udp, icmp)              |
| `--dport`               | Specifies the destination port to match                            |
| `--sport`               | Specifies the source port to match                                 |
| `-s` or `--source`      | Specifies the source IP address to match                           |
| `-d` or `--destination` | Specifies the destination IP address to match                      |
| `-m state`              | Matches the state of a connection (e.g. NEW, ESTABLISHED, RELATED) |
| `-m multiport`          | Matches multiple ports or port ranges                              |
| `-m tcp`                | Matches TCP packets and includes additional TCP-specific options   |
| `-m udp`                | Matches UDP packets and includes additional UDP-specific options   |
| `-m string`             | Matches packets that contain a specific string                     |
| `-m limit`              | Matches packets at a specified rate limit                          |
| `-m conntrack`          | Matches packets based on their connection tracking information     |
| `-m mark`               | Matches packets based on their Netfilter mark value                |
| `-m mac`                | Matches packets based on their MAC address                         |
| `-m iprange`            | Matches packets based on a range of IP addresses                   |
## System Logs
Logs of the activities on the system. Can determine:
- System behaviours
- Network activity
- User activity
- Abnormal activity
- Unauthorised logins
- Attempted attacks
- Clear text credentials
- Unusual file access (could reveal possible security breach)

Can also analyse this log after a penetration test to identify if any security events (intrusion detected, or system warnings) were triggered.

Should be configured to:
- Log the appropriate level
- Rotate logs to prevent log files becoming too large
- Store logs securely and protected from unauthorised access

Logs should be reviewed regularly to react quickly to the alerts.

Logs can be analysed with a variety of built-in tools (both desktop and CLI) including `tail`, `grep`, `sed`. Analysis of these logs could reveal security vulnerabilities, breaches, and other events of interest.
### Kernel Logs
**Contains:**
- Kernel information & events
- Hardware drivers
- System calls

**Location:**
- `/var/log/kern.log`

**Uses:**
- Reveal presence of vulnerable or outdated drivers
- System crash reports, resource limitations, etc (identify possible DoS or other security issues)
- Reveal suspicious system calls or activities that could suggest the presence of malware.

### System Logs
**Contains:**
- System-level events, eg:
	- Service stop & starts
	- Login attempts
	- System reboots

**Location:**
- `/var/log/syslog`

**Uses:**
- Identify failed service starts or system reboots (impact availability or performance of the system)
- Analysing events could reveal exploitable access or activities

### Authentication Logs
**Contains:**
- Authentication attempts (Failed & Successful logins)
- Commands run by users
- Disconnections
- Firewall alerts

**Location:**
- `/var/log/auth.log`

**Uses:**
- Reveal potential attacks
- Reveal unauthorised logins

### Application Logs
**Contains:**
- Logs about a particular application

**Location:**
- Often (but not necessarily) stored in `/var/log/<application>/`
- eg. `/var/log/apache2/error.log`

**Uses:**
- Very important when targeting a specific application for logged behaviours
- Access logs can track requests made by the web server
- Audit logs can track changes made to the system or specific files
- Can be used to identify unauthorised access attempts, data exfiltration, or other suspicious activity

### Security Logs
- Often recorded in a variety of log files depending on the tool or software being used:
	- `file2ban` records failed login attempts in `/var/log/fail2ban.log`
	- `UFW` firewall logs to `/var/log/ufw.log`
- Sometimes other security events such as file system changes or settings, may be in general logs like the `authlog` or `syslog`.
