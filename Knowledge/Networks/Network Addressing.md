```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 4 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Network Address Translation (NAT)
- Translates an IP address on a network to another IP address to be used on a different network ( eg. internal IP (private host IP) --> external IP (router IP for internet) )
- Router will read the Layer 3 information, *and if there is any NAT procedure*, it will modify the Src or Dst IP address
- Provides an additional layer of security, by preventing the real IP addresses of the systems on a network from being exposed across the internet
- Allows a network to expose a public IP address for each system OR just expose a single firewall IP address for the entire network

### Types of NAT
- **Static** address translation (Static NAT) : Allows for one-to-one mapping between local and global addresses.
- **Dynamic** address translation (Dynamic NAT) : Maps unregistered IP addresses to registered IP addresses from a pool of registered IP addresses.
- **Overloading** : Maps multiple unregistered IP addresses to a single registered address (many to one) using different ports (information is added in the Layer 4 data). This method is also known as Port Address Translation (PAT). By using overloading, thousands of users can be connected to the Internet by using only one real global IP address. Also requires the network to keep a database of the mappings.

## IPv4 Addresses
- Consist of 4 bytes ranging 0-255
- Divided into host & network parts
- Networks used to use a Class System (A-E) but now we use *Classless Inter-Domain Routing (CIDR)* which is the `0.0.0.0/x` part of the address, it defines how many bits of the address belong to the network.

| Class | Network Address | First Address | Last Address    | Subnet Mask   | Subnets   | CIDR | IPs           |
| ----- | --------------- | ------------- | --------------- | ------------- | --------- | ---- | ------------- |
| A     | 1.0.0.0         | 1.0.0.1       | 127.255.255.255 | 255.0.0.0     | 127       | /8   | 16,77,214 + 2 |
| B     | 128.0.0.0       | 128.0.0.1     | 191.255.255.255 | 255.255.0.0   | 16,384    | /16  | 65,534 + 2    |
| C     | 192.0.0.0       | 192.0.0.1     | 223.255.255.255 | 255.255.255.0 | 2,097,152 | /24  | 254 + 2       |

### Subnet Mask
- Describes which parts of an IP address is the *host part* (the actual network) & *network part* (the specific device)
- Class A : H.N.N.N : Mask = 255.0.0.0
- Class B : H.H.N.N : Mask = 255.255.0.0
- Class C : H.H.H.N : Mask = 255.255.255.0

### Network Address
This is the first IPv4 Address of a network. It isn't assigned to anything but identifies the network eg. `192.0.0.0`

### Default Gateway
This is the address of the network's router, usually the first or last *assignable* address of a network eg. `192.0.0.1` or `223.255.255.254`

### Broadcast Address
This address sends a packet to *ALL* addresses on the network. This is the last IPv4 Address eg. `223.255.255.255`

```
IP(b): 1100 0000 . 1010 0000 . 0000 0001 . 1011 0101
IP(d):    192    .    168    .     1     .    181
Subnet:   255    .    255    .    255    .     0
```
## Local Area Networks
### Network Addressing
- Layer 2 : Data Link Layer
	- Uses MAC addresses
- Layer 3 : Network Layer
	- Uses IP addresses
	- Most used protocols:
		- IPv4 / IPv6
		- IPsec
		- ICMP
		- IGMP
		- RIP
		- OSPF

1. Data is encapsulated within a packet header
2. Then the header is encapsulated within another header
3. IP packet is then encapsulated in a Layer 2 frame (eg. ethernet frame)
4. All encapsulated with physical information at Layer 1
5. This is then reversed on the receiving end

![[packet-address-information.png]]

| | Layer 2 Addresses | Layer 3 Addreses |
|-|-|-|
| Also known as | MAC Addresses; Hardware Addresses; Physical Addresses | IP Addresses; Logical Addresses |
| Example | 00:90:96:9f:ea:46 | 172.16.12.1 |
| Characteristics | Idenfity the stops made along the way; Change with each stop along the route | Identify the communicating computers or end points; Do not change (unless going through NAT) |
> Every time a packet enters a new **Layer 3** device, the Layer 2 information is stripped out and replaced with new source and destination addresses

### Ethernet Networks

**Ethernet (IEEE 802.3) Frame Format:**

| Preamble | SFD | Dst Addr | Src Addr | Length | Data | Checksum/CRC |
|-|-|-|-|-|-|-|
| 7 Bytes | 1 Byte | 6 Bytes | 6 Bytes | 2 Bytes | 46-1500 Bytes | 4 Bytes |

- **Preamble** - First 7 bytes of an Ethernet Frame, alternating between 0 and 1 allowing bit sync to happen and the receiver to lock onto the data-stream before the actual frame bits start.
- **Start of frame delimiter (SFD)** - 1-Byte field that is always set to `10101011`. This indicates the next bits are the destination address. Warns stations this is the last chance to sync.
> The SFD is often described as part of the preamble, making it the first 8-bytes
- **Dst Addr** - Contains the MAC address of the machine it is destined.
- **Src Addr** - MAC address of source machine. As Src Addr is always an individual address (Unicast), the least significant bit of first byte is always 0.
- **Length** - Entire length of Ethernet frame, can be a 16-bit value between 0 and 65534. Data cannot be longer due to limitations of Ethernet.
- **Data** - The Payload of the packet. Both IP header and data will be inserted here if Internet Protocol is used over Ethernet. Maximum length of 1500 bytes, and minimum of 46 bytes (0 padding will be added if data doesn't meet minimum length)
- **Checksum/CRC (Cyclic Redundancy Check)** - 32-bit hash code of the dst addr, src addr, length and data fields.

**Receiving a packet**
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
- Logical separation of devices in a network
- Could have 5 devices connected to a switch but you could create a VLAN containing 2 of the devices

### Address Resolution Protocol (ARP)
- Used to find the MAC address of devices within the same broadcast domain
- Simply maps an IP (L3) address to a MAC (L2) Address
- Can be viewed using the following command
```shell
arp -a
? (9.140.101.1) at 0:0:5e:0:1:1 on en0 ifscope [ethernet]
? (9.140.101.127) at 88:66:5a:4d:e2:f4 on en0 ifscope permanent [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (239.255.255.250) at 1:0:5e:7f:ff:fa on en0 ifscope permanent [ethernet]
```

1. Pings on the broadcast address to all devices on the network asking if they have the IP address being queried
2. The device with that address will respond with its MAC address

### Routing Tables
- If we don't know anything about the address it is sent to the default gateway by default which then routes it on