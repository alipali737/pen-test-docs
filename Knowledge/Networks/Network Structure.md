---
layout: page
title: Network Structure
parent: Networks
grand_parent: Knowledge
---
# {{ page.title }}
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

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