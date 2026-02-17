```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
A thick client application is one that is installed locally on a computer and doesn't necessarily require the internet to use. They are usually purpose-build enterprise applications developed in Java, C++, .NET, or Microsoft Silverlight. This allows for better performance, more features, and generally improved UX compared to thin clients (web apps).

*Java* runs in a virtual environment (a *sandbox*) which allows for isolation and execution of untrusted code without posing a security risk. This is also complemented by *Java API restrictions* and *Code signing* which can too help secure the environment.

*.NET* often refers to thick clients as *rich* or *fat* clients.
### Common Attack Vectors:
- Improper Error Handling
- Hardcoded sensitive data
- DLL Hijacking
- Buffer Overflows
- SQL Injection
- Insecure Storage
- Session Management

If a thick client interacts with a local or remote server, then there is still a potential for more traditional web app attacks 

## Recon and Enumeration
**Goals**:
- Identify application architecture
- Programming languages used
- Frameworks used
- Understanding how the application and infrastructure work / what it does.
- Identify technologies in use on both the client and server sides
- Identify entry points and user inputs

**Tools**:
- [CFF Explorer](https://ntcore.com/?page_id=388) : A *portable executable (PE)* editor for exploring headers and editing exe / dll files on windows.
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) : A binary file inspector and file type analysis that can give some early understanding.
- [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) : A windows tool for real-time monitoring of the file system, registry, and process/thread activity.
- [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings) : Scans the given file (exe, DLLs, binary files) for embedded ANSI and Unicode strings.

## Client Analysis
**Goals**:
- Reverse-engineer and examine application files
- Identify sensitive information and vulnerabilities in the application
- Identify any potential network interactions
- Dynamic analysis of the application

**Tools**:
- [Ghidra](https://www.ghidra-sre.org/) : Decompile, reverse-engineer, and analyse compiled files. Every extensible and full-featured suite.
- [Radare2](https://www.radare.org/n/radare2.html) : A handy CLI tool for easing low level reverse-engineer, exploring and debugging software. 
- [dnSpy](https://github.com/dnSpy/dnSpy) : A .NET debugger and assembly editor.
- [x64dbg](https://x64dbg.com/) : An x64/x32 debugger for windows.
- [JADX](https://github.com/skylot/jadx) : A tool for decompiling **Android DEX and APK files** to Java source code.
- [Frida](https://frida.re/) : A toolkit for interacting with compiled applications without needing their source code. Can hook functions, inject scripts, trace app code etc. *Works for mobile too.*

## Network Analysis
**Goals**:
- Capture any network traffic produced by the application
- Analyse the traffic for insecurities
- Gain further understanding to the application's functions

**Tools**:
- [Wireshark](https://www.wireshark.org/) : GUI network packet capture and analysis suite.
- [tcpdump](https://www.tcpdump.org/) : CLI for packet analysis and network traffic capture.
- [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) : Windows software for listing all TCP and UDP connections and their associated processes.
- [Burp Suite](https://portswigger.net/burp) : HTTP & WS traffic proxy

