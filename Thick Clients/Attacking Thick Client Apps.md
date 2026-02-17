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

## Recon and Enumeration
**Goal**:
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