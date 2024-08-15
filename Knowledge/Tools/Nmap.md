## The Scanning Phase
A security test follows the Hacking Process:
1. Reconnaissance
2. **Scanning**
3. Enumeration
4. System Hacking
5. Escalation of Privilege
6. Planting Backdoors
7. Covering Tracks

The scanning phase in a security test is to gain insights into the technical system data of systems on the network. Tools are used to scan for different technical network and system information. Dialers, Sweepers, Vulnerability scanners, and port scanners are all used in this phase.

## What is Nmap?
[Nmap](https://nmap.org/), Network Mapper, is a port scanner/network mapping tool. It is the most used scanning tool in the industry. It is an *open-source linux based cli tool*. The tool is designed to *scan systems/networks for IP addresses, system ports, OS details, and applications/services installed*.

## Why use Nmap?
It has the ability to perform highly sophisticated mapping functions that *aim to go undetected by IDS/IPS*, it can also perform simple network commands. The Nmap Scripting Engine (NSE) provides comprehensive scripting capabilities. Some key benefits of Nmap are:
- Ability to *identify specific services running* on a system: DNS, web, email, SSH, etc.
- Ability to *gather OS-specific details* of target system.
- The *Zenmap's GUI helps build visualisations of the scan results* of target networks/systems
- Ability to *identify and distinguish between different network devices*: routers, servers, switches, mobile devices, etc.
- The NSE. It allows for complex automation of Nmap's power. The *NSE uses Lua* for scripting.
- Reusable attack scripts from the NSE repository.

## Planning Before Scanning
The activity of scanning can also be called *Foot-printing*. Before any port scanning can be conducted it is **important to have a plan and objective**.

Foot-printing will help identify:
- Specific services used by the organisation
- Possible application versions
- Utilisation frequency by daytime
- And more

This information may help determine the target application, service, host. and/or port to locate on the network.

The first step before doing any detailed scans is to *map the network*. This will give you a list of all 'up' or active hosts on the network. *Port scanning on these hosts* can then be conducted. By *correlating the information* collected during foot-printing, specific scan types may be executed to *find the available ports on a system*.

### An Example
**The Example:**
- It is discovered that a target organisation is using *MS SharePoint 2003, a product that reached EoL in 2014*.
- Since its EoL two vulnerabilities have been reported in that version. When conducting scans a *public-facing SharePoint webpage was located with listening (open) port 8080*.

**Example Review:**
- After discovery of this potential weakness, the *objective was to locate any servers running SharePoint 2003*.
- *Nmap scans identified public-facing open ports*.
- Recommendations to either *upgrade or remove the SharePoint 2003* servers.

## Ports
Ports are between 0-65,535.

- **Ports 0 - 1023** (aka *Well-Known Ports*): Assigned to universal TCP/IP application protocols. Most common examples: HTTPS, SSH, FTP, DNS, etc. They are registered to these protocols by a global authority.
- **Ports 1024 - 49,151** (aka *Registered Ports*): Reserved for application protocols that are not specified as universal.
- **Ports 49,152 - 65,535** (aka *Private/Dynamic Ports*): These ports may be used for any process without registering the port with the global assigning authority.

## Using Nmap
A basic scan uses the following format:
{% highlight shell %}
nmap {Scan Type(s)} {options} [target]
{% endhighlight %}

Nmap can take targets as IPv4/IPv6/URLs/Fully Qualified Domain Name (FQDN).
### Ping Sweeping
{% highlight shell %}
nmap -sn [target range]
{% endhighlight %}

A ping sweep can be used to scan a network for available hosts, it does this by iterating through a range of addresses sending an *Internet Control Message Protocol (ICMP)* packet. It is a discovery scan.

<details>
	<summary>Example Ping Sweep</summary>
	{% highlight shell %}
	$ nmap -sn 192.168.1.1-254  
	Starting Nmap 7.70 ( https://nmap.org ) at 2022-06-01 13:01 EST  
	Nmap scan report for 192.168.1.96  
	Host is up (0.064s latency).  
	Nmap scan report for 192.168.1.118  
	Host is up (0.029s latency).  
	Nmap scan report for 192.168.1.128  
	Host is up (1.18s latency).  
	Nmap scan report for 192.168.1.171  
	Host is up (0.0094s latency).  
	Nmap scan report for 192.168.1.179  
	Host is up (0.064s latency).  
	Nmap scan report for 192.168.1.210  
	Host is up (0.0066 latency).  
	Nmap scan report for 192.168.1.253  
	Host is up (0.0049 latency).  
	Nmap done: 254 IP addresses (7 hosts up) scanned in 7.90 seconds
	{% endhighlight %}
</details>

### TCP Connect Scan
{% highlight shell %}
nmap -sT [target]
{% endhighlight %}

TCP establishes a 3-way handshake. Nmap uses this handshake to determine if a port is open:

| Nmap | | Server |
|-|-|-|
| SYN (request port 22 connection) | --> ||
|| <-- | SYN/ACK (Port is open, Go ahead!) |
| ACK (Connection Established) | --> ||
|| <-- | Data: SSH banner message |
| RST (Kill Connection) | --> ||

### TCP SYN Scan (Stealthy alternative)
{% highlight shell %}
nmap -sS [target]
{% endhighlight %}

This scan type only performs a partial 3-way handshake, unlike the TCP Connect Scan. It does this by never sending the final ACK packet upon receipt of the SYN/ACK response from the server.

| Nmap | | Server |
|-|-|-|
| SYN (request port 22 connection) | --> ||
|| <-- | SYN/ACK (Port is open, Go ahead!) |
| RST (Kill Connection) | --> ||

## Scripting with Nmap NSE
*Nmap Scripting Engine (NSE)* is an important feature of Nmap as it allows for complex automation of various networking tasks. These could range from finding vulnerabilities in networks, identifying possible backdoors, or exploiting a vulnerability in a target system.

Nmap uses *Lua* as its scripting language as it has been embedded into the engine.

Some benefits to scripting with Nmap:
- More flexibility and efficiency with network discovery and security audits
- Can be more *proactive* rather than *reactive* when dealing with system vulnerabilities
- Cover more ground with less effort

For example, a script could be created to take action if a network vulnerabilities is found within a system.

The Nmap help page gives us some basics for *SCRIPT SCAN*ning. We can:
- Provide script file(s)
- Provide arguments to scripts
- Provide NSE script arguments in a file
- Show all data sent and recieved
- Update a script database
- Get help with scripting

{% highlight shell %}
SCRIPT SCAN:  
  -sC: equivalent to --script=default  
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of  
           directories, script-files or script-categories  
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts  
  --script-args-file=filename: provide NSE script args in a file  
  --script-trace: Show all data sent and received  
  --script-updatedb: Update the script database.  
  --script-help=<Lua scripts>: Show help about scripts.  
           <Lua scripts> is a comma-separated list of script-files or  
           script-categories.
{% endhighlight %}

More detail can be found on the [Nmap Scripting Engine website](https://nmap.org/book/man-nse.html).

The `-sC` flag specifies that for every service discovered, run the default script. This could be useful in finding out additional information about a service eg. It could discover HTTP headers, email information from a page etc

### Creating Scripts in Lua

The anatomy of an NSE Script:
{% highlight lua %}
-- HEAD

-- RULES

-- ACTION
{% endhighlight %}

#### The HEAD
The `HEAD` section of the script contains meta information about your script

- `require` statements specify dependencies
{% highlight lua %}
local package1 = require "package1"
local package2 = require "package2"
{% endhighlight %}

- `description` is a variable that describes what the script does
{% highlight lua %}
description = [[
	Detailed description here!
]]
{% endhighlight %}

- `author`, `license`, and `categories` variables
{% highlight lua %}
author = "Your Name"

license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

categories = {"default", "safe"}
{% endhighlight %}

[We can see some common categories on the Nmap website](https://nmap.org/book/nse-usage.html). By adding the category `"default"`, this script would run when we use the `-sC` or `-A` configuration options. We’ll also say this script is `"safe"` because we aren’t planning to crash or hurt anything with our script!

#### The RULES
The `RULES` of the script is the portion of the code that determins if the script will run or not. For example, if port 80 isn't open, maybe we can't run out HTTP-specific script. In that case, we should terminate the script.

The script will always include one of:
- `prerule()` - This rule runs during the pre-scanning phase, before any hosts have been scanned. Useful for discovery scripts.
- `hostrule(host)` - This rule runs after each batch of hosts have been scanned.
- `portrule(host, port)` - This rule runs after each batch of ports have been scanned.
- `postrule()` - This rule is checked after the scan has completed. Useful for any scripts reviewing the full results of a scan.

#### The ACTION
This is where the actual functionality of the script is defined. If the RULE passes, then this section will be executed.

#### Hello World Script Example
{% highlight lua %}
-- HEAD
local nmap = require "nmap"

description = [[
  "Hello world script"
]]

author = "alipali737"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

-- RULES
portrule = function(host, port)
  local port_to_check = { number = 4000, protocol = "tcp" }
  local port_state = nmap.get_port_state(host, port_to_check)

  return port_state ~= nil and port_state.state == "open"
end

-- ACTION
action = function(host, port)
  return "Hello, port "..port.number.."!"
end
{% endhighlight %}
