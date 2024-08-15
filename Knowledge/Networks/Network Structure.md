```table-of-contents
```
## Network Types
### Wide Area Network (WAN)
- eg. The internet
- Large number of LANs connected.
- Uses an IP schema not within **RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)**

### Local Area Network (LAN)
- Can also be a Wireless LAN (WLAN)
- Typically use RFC 1918
- Single site

### Virtual Private Network (VPN)
#### Site-To-Site VPN
- Client and Server are network devices (eg. routers & firewalls)
- Typically to join company networks together over multiple locations

#### Remote Access VPN
- Creates a virtual interface that mimics the remote network
- If a VPN only creates routes for specific networks (eg. 10.10.10.0/24) then its a *Split-Tunnel VPN*
	- The internet connection is left outside the VPN (not ideal for network-based detection methods for malware)

#### SSL VPN
- VPN done through the browser (eg. connecting to a virtual machine on a website)
- Streams apps or desktop sessions over the browser

### Global Area Network (GAN)
- Eg. the internet
- Connect multiple WANs together (eg. an international company network) using under-sea cables

### Metropolitan Area Network (MAN)
- Connects multiple LANs in geographic proximity.
- Eg. a city-wide network

### Personal Area Network (PAN)
- Adhoc data (eg. Mobile roaming data)
- Can also be Wireless (WPAN) eg. Bluetooth or Wireless USBs.
- Usually only a few meters

## Proxies
A proxy is a device that sits in the middle of a connection as a *mediator*. A mediator is able to inspect the contents of traffic, without this feature, it is just a gateway.

Tools like *Burp Suite* are a swiss army knife of HTTP proxies for security testers, allowing you to configure it to be any type of proxy.
### Dedicated Proxy / Forward Proxy
A forward proxy is when a client makes a request to a computer, and the computer then carries out the request (filtering outgoing requests). Eg. a sensitive device in a company may use a forward proxy to not have direct access to the internet, allowing for better malware protection and/or web filtering.

Lots of malware aren't *proxy aware* meaning that they won't detect they are on a proxy instead of their intended target. Adding a proxy allows for more traffic monitoring and could catch malware much easier.
![[forward-proxy.png]]

### Reverse Proxy
The reverse of a forward proxy, it filters the incoming requests. Most commonly it is used to listen on an address and forward traffic to a closed-off network. Many organisations use *Cloudflare* as a reverse proxy and filter the traffic to their web-exposed applications.

Penetration Testers will use reverse proxies on infected endpoints. The infected endpoint will listen on a port and send any client that connects to the port back to the attacher through the endpoint. This allows the evasion of logging techniques and bypassing firewalls. If an attacker gains access to an organisation over SSH, a reverse proxy can send web requests through the SSH tunnel and evade the *IDS*.

Another common use of reverse proxies is as a *Web Application Firewall (WAF)*. This will attempt to filter out malicious web traffic before it reaches the application.
![[reverse-proxy.png]]
