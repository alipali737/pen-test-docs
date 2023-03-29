---
layout: page
title: TCP/IP Framework
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
``` 
     OSI MODEL              TCP/IP Layers
+---+-------------+      +---+-------------+
| 7 | Application |      | - | ~~~~~~~~~~~ |
| 6 | Presentation|      | 4 | Application |
| 5 | Session     |      | - | ~~~~~~~~~~~ |
| 4 | Transport   | <--> | 3 |  Transport  |
| 3 | Network     | <--> | 2 |   Network   |
| 2 | Data Link   | <--> | - |  -Network-  |
| 1 | Physical    | <--> | 1 |  Interface  |
+---+-------------+      +---+-------------+
```

## Packet Inspection
### Stateless Inspection
- Each packet is inspected one at a time, independently of any other packet knowledge
- No session tables are maintained, no database of previous packets inspected
- Much faster than stateful inspection, no need to check databases

#### What is inspected?
- Source IP address
	- Access Control List rule determins if an IP is allowed into the network or if dst IP is allowed to be accessed
- Destination port / service

#### Use Cases
- To protect routing engine resources
- To control traffic going in or out your network
- For troubleshooting purposes when classifying packets
- To control traffic routing (through the use of routing instances)
- To perform QoS/CoS (marking traffic priorities)

### Stateful Inspection
- Each packet is inspected with knowledge of all the previous packets in that session

#### Sessions
- A session contains all the packets exchanged between the parties in an exchange
- Contains:
	- Src IP & Port
	- Dst IP & Port
	- [Optional] Instance Identifyer
- A session ID can be used to locate the session information from the firewall packet database

{% highlight shell %}
$ show security flow session application telnet
Session ID: 57866, Policy name: intrazone-Juniper-SV/4, Timeout: 3394, Valid
In: 172.20.107.10:56290 --> 172.20.207.10:23;tcp, If: vlan.107, Pkts: 27, Bytes: 1568
Out: 172.20.207.10.23 --> 172.20.107.10:56290;tcp, If: lt-0/0/0.1, Pkts: 21, Bytes: 1543
{% endhighlight %}

### Using both Stateful & Stateless together
- Stateless inspection is performed first
- Then Stateful data is evaluated

## IDS vs IPS Systems
#### IDS - Intrusion Detection System
- Network security technology originally built for detecting vulnerability exploits against a target application or computer.
- Listen-only device
- Most often, the IDS is a dedicated server that is connected to a port on a switch.
- The switch forwards a copy of all traffic to the IDS for inspection
- Monitors traffic (looking for anomolus behaviour) and then notifies an administrator
- Cannot automatically take action to prevent a detected exploit from taking over the system
> Some modern IDS' can run scripts, eg. that send a command to block an IP address to the router

#### IPS - Intrusion Prevention System
- Network security/threat prevention technology that examines network traffic to detect and prevent vulnerability exploits.
- IPS sits inline in a network, meaning all traffic MUST pass through it first before it can then move on (this adds a delay to the traffic)
- Positioned right after an edge device, router or firewall (Some firewalls are designed to act like an IPS)
- Unlike an IDS, the IPS actively analyzes packets, taking automated actions on all traffic flows that enter the network
| | IPS | IDS |
|-|-|-|
| Placement in the network infrastructure | Part of the direct line of communication (inline) | Outside direct line of communication (offline) |
| System Type | Active (monitors and automatically defends) and/or passive | Passive (monitors and notifies) |
| Detection mechanism | Statistical anomaly-based detection; Signature detection: Explit-facing signature, Vulnerability-facing signature | Anomaly based |

### IPS Defences
- Can automatically create an ACL to block traffic that has been identified as malicious
- In passive mode, it will just notify the admin

### Detection Methods
#### Anomaly-Based
- Detect if a protocol's standards are not being followed
- eg. Lots of half opened TCP sessions, HTTP arrives with an unexpectedly long header or missing headers

#### Signatures
- Contain a database of signatures that are malicious
- Patterns that can be found in the payload of traffic

#### Host-Based IDS (H-IDS)
- Software based solutions installed on a host to defend it from attack
- Listens to the traffic being recieved by or sent from the endpoint, and takes action/alerts where needed

#### Network-Based
- Hardware based
- IDS - sits on the side and recieved a copy of the traffic
- IPS - sits on the line and actively analyses traffic

### Firewall Filters
- Many modern firewall designs have a `Control Plane` and a `Forwarding Plane`
- The **Forwarding Plane** is responsible for all routing decisions, forwarding the packets on, policy evaluations, session matching etc
- The **Control Plane** runs the device operating system and holds the routing table, if this plane becomes unavailable the device can still forward traffic as the Plane's are seperate

## Network Address Translation (NAT)
- Translates an IP address on a network to another IP address to be used on a different network ( eg. internal IP (private host IP) --> external IP (router IP for internet) )
- Router will read the Layer 3 information, *and if there is any NAT procedure*, it will modify the Src or Dst IP address
- Provides an additional layer of security, by preventing the real IP addresses of the systems on a network from being exposed across the internet
- Allows a network to expose a public IP address for each system OR just expose a single firewall IP address for the entire network

### Types of NAT
- **Static** address translation (Static NAT) : Allows for one-to-one mapping between local and global addresses.
- **Dynamic** address translation (Dynamic NAT) : Maps unregistered IP addresses to registered IP addresses from a pool of registered IP addresses.
- **Overloading** : Maps multiple unregistered IP addresses to a single registered address (many to one) using different ports (information is added in the Layer 4 data). This method is also known as Port Address Translation (PAT). By using overloading, thousands of users can be connected to the Internet by using only one real global IP address. Also requires the network to keep a database of the mappings.

## Local Area Networks
### Network Addressing
- Layer 2 : Data Link Layer
	- Uses MAC addresses
- Layer 3 : Network Layer
	- Uses IP addresses

1. Data is encapsulated within a packet header
2. Then the header is encapsulated within another header
3. IP packet is then encapsulated in a Layer 2 frame (eg. ethernet frame)
4. All encapsulated with physical information at Layer 1
5. This is then reversed on the recieving end

![Packet Address Information]({{ site.baseurl }}/assets/images/networks/packet-address-information.png)

| | Layer 2 Addresses | Layer 3 Addreses |
|-|-|-|
| Also known as | MAC Addresses; Hardware Addresses; Physical Addresses | IP Addresses; Logical Addresses |
| Example | 00:90:96:9f:ea:46 | 172.16.12.1 |
| Characteristics | Idenfity the stops made along the way; Change with each stop along the route | Identify the communicating computers or end points; Do not change (unless going through NAT) |
> Everytime a packet enters a new **Layer 3** device, the Layer 2 information is stripped out and replaced with new source and destination addreses

### Ethernet Networks

**Ethernet (IEEE 802.3) Frame Format:**

| Preamble | SFD | Dst Addr | Src Addr | Length | Data | Checksum/CRC |
|-|-|-|-|-|-|-|
| 7 Bytes | 1 Byte | 6 Bytes | 6 Bytes | 2 Bytes | 46-1500 Bytes | 4 Bytes |

- **Preamble** - First 7 bytes of an Ethernet Frame, alternating between 0 and 1 allowing bit sync to happen and the reciever to lock onto the datastream before the actual frame bits start.
- **Start of frame delimiter (SFD)** - 1-Byte field that is always set to `10101011`. This indicates the next bits are the destination address. Warns stations this is the last chance to sync.
> The SFD is often described as part of the preamble, making it the first 8-bytes
- **Dst Addr** - Contains the MAC address of the machine it is destined.
- **Src Addr** - MAC address of source machine. As Src Addr is always an individual address (Unicast), the least significant bit of first byte is always 0.
- **Length** - Entire length of Ethernet frame, can be a 16-bit value between 0 and 65534. Data cannot be longer due to limitations of Ethernet.
- **Data** - The Payload of the packet. Both IP header and data will be inserted here if Internet Protocol is used over Ethernet. Maximum length of 1500 bytes, and minimum of 46 bytes (0 padding will be added if data doesn't meet minimum length)
- **Checksum/CRC (Cyclic Redundancy Check)** - 32-bit hash code of the dst addr, src addr, length and data fields.

**Recieving a packet**
1. *Layer 1* : Converts the signals to data and passes the frame to layer 2
2. *Layer 2* : Checks that the Dst MAC addr is the same as its own MAC addr, if so it strips off the layer 2 data and forwards the data as a packet to Layer 3
3. *Layer 3* : Checks that the Dst IP Addr is the same as its own, if so strips the L3 data and forwards to L4
- If Dst MAC or Dst IP addr doesn't match the systems own addr the packet will be discarded as its not intended for that system

#### MAC Addresses
- 48-bit address that uniquly identifies every NIC. 
- First 3 bytes are for the OUI and last 3 bytes are reserved to identify each NIC.

**00:90:69:9f:ea:46** example:
- 00:90:69 - Identifies the manafacturer; Organizationally Unique Identifier (OUI)
- 9f:ea:46 - Identifies the unique NIC

#### Communication Methods
- **Unicast** - 1-1 cast, only talking to one other device on a network
	- Uses MAC & IP of dst device
- **Broadcast** - 1-All cast, sends a message to all devices on a network
	- Uses Maximum MAC Value (`FF:FF:FF:FF:FF:FF`) and boardcast IP address (`x.x.x.255` by default)
- **Multicast** - 1-Many cast, sends a message to all specified devices on a network
	- Devices can subscribe to an endpoint (a specific class-D range IP)
	- The MAC address always begins with `01-00-5E` for multicast and the last 3 bytes are created by converting the lower 23 bits of the IP multicast group address into 6 hex characters.

- **Half-duplex** - Unable to transmit and recieve at the same time, traffic can only flow in one direction at a time.
- **Full-duplex** - Can transmit and recieve data at the same time, traffic and flow in either direction at the same time.

### Network Devices on a LAN
- **Hub** - Takes the input data from one port and broadcasts it to all other ports on the network
- **Amplifier** - Amplifies the input signal, this also amplifies any noise
- **Repeater** - Takes the input signal and regenerates it, eliminating any noise in the signal
- **Bridge** - Only sends the signal to the port the dst computer is connected too, it contains a MAC table so it knows where each device is in the network
- **Switch** - Upgrade over the bridge, network loops are still an issue, they might not improve performance with multicast and broadcast traffic, cannot connect geographically dispersed networks

| Bridge | Switch |
|-|-|
| Half-duplex data transmission | Full-duplex data transmission |
| End-user devices share bandwidth on each port | Each port is dedicated to a single device; bandwidth is not shared |
| Virtual LANs are not possible | Virtual LANs are possible |

### Virtual LANs
- Logical seperation of devices in a network
- Could have 5 devices connected to a switch but you could create a VLAN containing 2 of the devices

### Address Resolution Protocol (ARP)
- Used to find the MAC address of devices within the same broadcast domain
- Simply maps an IP (L3) address to a MAC (L2) Address
- Can be viewed using the following command
{% highlight shell %}
arp -a
? (9.140.101.1) at 0:0:5e:0:1:1 on en0 ifscope [ethernet]
? (9.140.101.127) at 88:66:5a:4d:e2:f4 on en0 ifscope permanent [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (239.255.255.250) at 1:0:5e:7f:ff:fa on en0 ifscope permanent [ethernet]
{% endhightlight %}

1. Pings on the broadcast address to all devices on the network asking if they have the IP address being queried
2. The device with that address will respond with its MAC address

### Routing Tables
- If we don't know anything about the address it is sent to the default gateway by default which then routes it on