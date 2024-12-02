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

## Meterpreter
The *Meterpreter* payload is a specific type of multi-faceted payload. It utilises DLL injection to ensure a stable, persistent across reboots connection. It has a variety of features built in such as key loggers, hash collection, tapping etc. It runs only in-memory so it is harder to find any forensic traces. We can also load and unload additional scripts and plugins dynamically.
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
> Get more info on a module by using `info`, this is critical for understanding a new module before it is used
> 
### Configuring a module
```
show options

set [OPTION] [value]
set RHOSTS 10.0.9.4
```
> `setg` can be used to set the option value globally, making it accessible for every module until the program is restarted (helpful for working against a specific target)
> `show targets` will present a list of all the target types that module can handle, we can set a target using `set target X`

### Selecting a payload
Before selecting a specific payload, we need to understand:
- What platform are we on?
- What architecture do we need?
- What are we trying to achieve?
- Staged or Single?

Once we know this we can search for a payload
```sh
# Shows all payloads that could be used (hundreds)
show payloads

# Use grep to filter
grep meterpreter show payloads
grep windows/x64 grep reverse_tcp grep meterpreter show payloads

# Select a payload within a module
set payload X
```
> Once a payload is selected, don't forget to configure it `show options`
### Running an exploit
```
run

check (used to check if the target is vulnerable before exploiting)

exploit
```

If an exploit has run successfully, we will be given a `meterpreter` shell (like Bash, PowerShell etc), we can use `?` to see the available commands but if we want a proper system-level shell, we can use `shell`.