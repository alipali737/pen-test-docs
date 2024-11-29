```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
The metasploit framework contains a ton of modules for public exploits and useful pen testing utilities.

[[MSFvenom]] is a part of the metasploit framework specifically for creating payloads.

Modules are structured by their path:
`exploit/windows/smb/psexec` would break into:
- *exploit* : module will attempt to create a shell session
- *windows* : the targeted platform
- *smb* : the target service
- *psexec* : the tool being uploaded.

[This](https://docs.metasploit.com/docs/modules.html) document summarises the modules and their structure, in short:
- *Auxiliary* modules : Do not exploit a target but perform useful tasks
	- Administration : modify, operator or manipulate target system
	- Analysing : mostly password cracking
	- Gathering : collect, enumerate, gather data
	- DoS
	- Scanning : vulnerability scanning
	- Server Support : run common protocol servers (eg. SMB, FTP)
- *Encoder* modules : Used to encode raw bytes of a payload and run encoding algorithms
- *Evasion* modules : Generates evasive payloads
- *Exploit* modules : Modules that attempt to execute arbitrary code on the target via vulnerabilities
- *Nop* modules : Create nop instructions (often used in stack buffer overflows)
- *Payloads* modules : The actual payloads executed by exploit modules (often getting shells but can add accounts etc)
- *Post* modules : Post-exploitation modules for gathering, collecting, or enumerating data from a session
## Installation
```
sudo apt install metasploit -y
```
Sometimes an exploit wont be in our version of MSF so we can update it via:
```
sudo apt update && sudo apt install metasploit-framework
```
Alternatively, we can directly add exploits
```
locate exploits
/usr/share/metasploit-framework/modules/exploits

cp [exploit_file.rb] [exploits_path]
cp rconfig_vendors_auth_file_upload_rce.rb /usr/share/metasploit-framework/modules/exploits/linux/http/
```
## Documentation
**Cheatsheet:** 
**Website:** 

> [!info]- Engagement process with Metasploit
> ![[Pasted image 20241129144818.png]]

## Usage
### Initialise the msf console
```
sudo msfconsole
```

### Searching
```
search [filters] [name]
search exploit eternalblue
search openssh
search cve:2009 type:exploit vsftpd
```

### Using an module
```
use [path/to/module]
```

### Configuring a module
```
show options

set [OPTION] [value]
set RHOSTS 10.0.9.4
```
> `setg` can be used to set the option value globally, making it accessible for every module until the program is restarted (helpful for working against a specific target)
### Running an exploit
```
run

check (used to check if the target is vulnerable before exploiting)

exploit
```

If an exploit has run successfully, we will be given a `meterpreter` shell (like Bash, PowerShell etc), we can use `?` to see the available commands but if we want a proper system-level shell, we can use `shell`.