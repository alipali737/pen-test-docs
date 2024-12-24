```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

> A process of performing detailed searches across the file system and various applications to discover credentials.

Many search features are built into applications or windows itself and can be used to identify user credentials or default credentials that have been stored on the file system.

It is important to consider the context of the target:
- What might the target's user being doing on a day-to-day? 
- What may require credentials?

**Useful key terms**
- passwords
- passphrases
- keys
- username
- user account
- creds
- users
- passkeys
- configuration
- dbcredential
- dbpassword
- pwd
- login
- credentials

## Search Tools
**Windows Search**
This can be useful for searching for key terms across the OS.

**Lazagne**
[Lazagne](https://github.com/AlessandroZ/LaZagne) is a tool (*worth keeping a standalone copy we can transfer over*) that can search for credentials that web browsers or other applications may install insecurely. The github page for the tool displays all the supported applications.

```cmd
C:\> start lazagne.exe all
```
> `-vv` can be used to study what is happening in the background.

**Findstr**
A built-in cli tool that can search for strings in files.
```cmd
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg
```

