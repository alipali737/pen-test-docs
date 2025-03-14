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

[[MSFVenom]] is a part of the metasploit framework specifically for creating payloads.

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

msf6> loadpath /usr/share/metasploit-framework/modules
OR
msf6> reload_all
```
## Documentation
**Cheatsheet:** 
**Website:** 
[Metasploit - The Penetration Tester's Guide](https://nostarch.com/metasploit)
> [!info]- Engagement process with Metasploit
> ![[Pasted image 20241129144818.png]]

## Meterpreter
![[Meterpreter#Summary]]
## Encoders
Encoders make payloads compatible with a variety of architectures as well as helping with AV evasion. Although, detection methods have grown and become more effective, encoding is still a very important aspect of payload execution.

Encoders can be specified when generating a payload in [[MSFVenom]] using the `-e` flag. A very popular encoder is `shikata_ga_nai` (*SGN*) which is described more [here](https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html). We can see what encoders are available for a specific *exploit module + payload* combination using `show encoders`.

## Plugins
Plugins by default are pre-installed into the `/usr/share/metasploit-framework/plugins` directory (custom plugins can be copied in). Once a plugin is in here, you can load it in metasploit with `load <plugin>`.

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

We can also search for exploits on the ExploitDB using the CLI which we can directly import into `msfconsole`:
```bash
# Search for exploits not including python files (we want Ruby files for msfconsole)
searchsploit -t <name> --exclude=".py"
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
```bash
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

### Scanning a payload for possible detection
[VirusTotal](https://www.virustotal.com/gui/home/upload) is a website that you can upload a file too and it will show you whether an AV would detect it. MSF has a built in `msf-virustotal` tool to check our payloads like this.
```
msf-virustotal -f <API_Key> -f <Payload File>
```


### Using databases in Metasploit
Databases in Metasploit present a way to store scan results, credentials, entrypoints etc. It can be really useful in large engagements to keep track of previous actions and discoveries.
```bash
# Ensure that the postgreSQL service is running
sudo service postgresql status
sudo systemctl start postgresql

# Initialise a metasploit database (update metasploit if broken)
sudo msfdb init
sudo msfdb status

# Run the database
sudo msfdb run

# In msfconsole you can interact with the database
help database

# Import Nmap scan results (.xml result works best)
db_import Scan.xml

# Backup and extract data from DB (useful after session for backups)
db_export -f xml backup.xml

# Can also call nmap inside metasploit
db_nmap
```
> The `hosts` command will show us all hosts, IPs, hostnames etc that have been identified and stored in the DB, we can do a number of things with `hosts -h`.
> The `services` command will show us services discovered.
> The `creds` command will show us any credentials we've found for the target host.
> The `loot` command provides an *at-a-glance* list of owned services and users. It can be hashes, passwd, shadow etc (Any loot we have collected).

### Workspaces
Workspaces are like folders in a project, they are useful for organising our results. We can segregate scan results, hosts and extracted information by IP, subnet, network, or domain.
```bash
# View current workspace
workspace

# Add / Delete a workspace
workspace -a target_1
workspace -d target_3

# Switch workspace
workspace target_1
```

### Sessions
- To background a session you can use either `[CTRL] + [Z]` or `background` (in meterpreter).
- List sessions with `sessions`
- Select a session with `sessions -i [no.]`
- Some modules (mostly in the `post` category) can have a session associated with them in the options

### Jobs
If we are running a module that requires a port but we want to use that port for something else now, we can't just kill the session with `[CTRL] + [C]` as this would leave the port still in use. Instead, we can use jobs. Jobs are backgrounded processes that can live on even after a session dies.
```bash
# Help page
jobs -h

# List all running jobs
jobs -l
```
We can run an exploit as a job using the `-j` flag on a the `exploit` command

## Useful Modules
- `multi/handler` - setup a listener for a reverse shell payload (generated with [[MSFVenom]])
- `post/multi/recon/local_exploit_suggester` - searches for potential exploits on a system (a meterpreter session works best on windows, whereas a shell session works best on other platforms)

## Writing custom exploit scripts
All exploit scripts are written in Ruby and documentation can be found on the [Rapid7 Rubydocs](https://www.rubydoc.info/github/rapid7/metasploit-framework/).