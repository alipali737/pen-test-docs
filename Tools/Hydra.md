```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Summary
Hydra is a fast network login cracker that supports numerous attack protocols (eg. HTTP, SSH, FTP).

## Installation
```
sudo apt-get -y update
sudo apt-get -y install hydra
```

## Documentation
**Cheatsheet:** 
**Website:** 
## Usage
```bash
hydra [login_options] [password_options] [attack_options] [service_options]
```
> `-l [user]` : use a single username
> `-L [user_list]` : use a username list
> `-p [pass]` : use a single password
> `-P [pass_list]` : use a password list
> `-t [threads]` : number of parallel tasks
> `-f` : stop after first success
> `-s [port]` : specify non-default service port
> `-v` : verbose (shows progress, attempts and results - use `-V` for even more)
> `[service]://[server]` : specify a service and target (eg. `ssh://192.168.1.100`)

### HTTP Post
```bash
[domain] http-post-form "/[path]:[data]:[conditition]"
www.example.com http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"
```
> For the condition, we can either use `F=` for failure strings or `S=` for success (although failure is more common). This can also be status codes, eg. `S=302` if it redirects after success.
### HTTP Basic Auth
```
hydra -l user -P passwords.txt www.example.com http-get /
```

### Multiple Targets
```bash
hydra -l root -p root -M targets.txt ssh
```