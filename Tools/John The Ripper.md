```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
John is a tool for checking the strength of and cracking encrypted (or hashed) passwords. It utilises brute force or dictionary attacks.

### John VS Hashcat
Both tools have their use cases, the primary points for each are:

| Tool                | Pros                                                                                                                                                                               | Cons                                                                                                                                                          | Recommended use case                                                                                                                                              |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [[John The Ripper]] | Supports more hashes<br>Supports most OS's<br>Able to do in-house hash detection<br>Takes advantage of CPU specific optimisations                                                  | GPU support for only specific hashes<br>Some hashes need to be converted first (which can be difficult to work out which tool to use)<br>CUDA is a pain       | CPU driven cracking<br>Hashes that aren't available in Hashcat<br>Wordlist usage                                                                                  |
| [[Hashcat]]         | Fantastic GPU support<br>Supports most compute binaries (open CL, Apple Metal, etc)<br>Supports most OS's<br>Supports lots of hash types<br>Able to detect hashes with second tool | Hash detection isn't great<br>Some device drivers lower performance (not HC's fault)<br>Potentially slower for wordlist attacks due to drive -> GPU bandwidth | A powerful GPU is available.<br>Brute-force & rule attacks that generate candidates on the GPU.<br>Linux with AMD GPU is ideal.<br>NTLMv2 & WPA hashes are faster |

## Documentation
**Cheatsheet:** 
**Website:** https://github.com/openwall/john
## Usage
### Single Crack Mode
This is the simplest mode to run, it take a list of hashes to crack and a single wordlist (*or uses it's built-in list*).
```bash
john --format=<hash_type> <hashes_file>
john --format=sha256 hashes_to_crack.txt
```
> We can use `--wordlist` and `--rules` to further configure the tool 

### Wordlist Mode
This mode uses a (*or multiple*) wordlist(*s*) to crack the hashes. It is typically best for multiple hashes to be cracked at the same time. We can also use the built-in `--rules` to generate additional candidates from our wordlist (eg. adding numbers, capitalisations, or special characters).
```bash
john --wordlist=<wordlist(s)> --rules <hash_file>
john --wordlist=rockyou.txt --rules hashes.txt
john --wordlist=list1.txt,list2.txt,list3.txt --rules hashes.txt
```

### Incremental Mode
This takes a character set and generates passwords from it, it starts with the shortest. It is the most effective but also the most time consuming. It is faster than the random brute force attempt, especially against weak passwords.
```bash
john --incremental <hash_file>
```
> The default char set is `a-zA-Z0-9`.

### Preparing a file for cracking
There are many tools that convert different file types to a format compatible with John, eg:
- `pdf2john`
- `ssh2john`
- `rar2john`
- `zip2john`
- `office2john` : for any password protected Microsoft office documents
```bash
pdf2john server_doc.pdf > server_doc.hash
john server_doc.hash
```
> Use `locate *2john*` to find these tools pre-installed.


## Side Note
If you are trying to crack an `openssl` encrypted archive, then it is more reliable to use `openssl` in a `for-loop` than through a tool like [[John The Ripper]] or [[Hashcat]].
```bash
$ for i in $(cat <wordlist>); do openssl enc -aes256 -d -in <archive_file> -k $i 2>/dev/null | tar xz;done
```