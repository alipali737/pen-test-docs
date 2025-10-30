```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Command Injection Methods
Take this example in an application
```bash
ping -c 1 [user_input]
```

| Operator   | Character | URL-Encoded | Executed Command                           |
| ---------- | --------- | ----------- | ------------------------------------------ |
| Semicolon  | `;`       | `%3b`       | Both (*Won't for for Windows CMD*)         |
| New Line   | `\n`      | `%0a`       | Both                                       |
| Background | `&`       | `%26`       | Both (second output generally shown first) |
| Pipe       | \|        | `%7c`       | Both (only second output is shown)         |
| AND        | `&&`      | `%26%26`    | Both (only if first succeeds)              |
| OR         | \|\|      | `%7c%7c`    | Second (only if first fails)               |
| Sub-Shell  | ``        | `%60%60`    | Both (*Linux-Only*)                        |
| Sub-Shell  | `$()`     | `%24%28%29` | Both (*Linux-Only*)                        |
## Most Common Injection Operators

| Injection Type                          | Operators                                          |
| --------------------------------------- | -------------------------------------------------- |
| SQL Injection                           | `'` `,` `;` `--` `/*` `*/`                         |
| Command Injection                       | `;` `&&`                                           |
| LDAP Injection                          | `*` `( )` `&` \|                                   |
| XPath Injection                         | `'` `or` `and` `not` `substring` `concat` `count`  |
| OS Command Injection                    | `;` `&` \|                                         |
| Code Injection                          | `'` `;` `--` `/*` `*/` `$()` `${}` `#{}` `%{}` `^` |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00`                                 |
| Object Injection                        | `;` `&` \|                                         |
| XQuery Injection                        | `'` `;` `--` `/*` `*/`                             |
| Shellcode Injection                     | `\x` `\u` `%u` `%n`                                |
| Header Injection                        | `\n` `\r\n` `\t` `%0d` `%0a` `%09`                 |
## Filters
- If we get a response back within the app itself, then its likely a filter in the code.
	- If its a filter, we can identify what we changed in the request and then attempt to bypass each one and see if it passes.
	- Its important here to try to do one character at a time, not the entire string. This allows us to check exactly which things are being blocked.
- If we get a different error page instead, with other information like IP or request, then its likely being blocked by a WAF.

### Bypassing Space Filters
- Use tabs instead of spaces : `%09`
- `${IFS}`'s default value is a space so we can just replace it where we would put spaces (*Linux-Only*)
- Brace expansion automatically adds spaces between elements when expanded (eg. `{ls,-la}` -> `ls -la`)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) has a section on writing commands without spaces

### Bypassing Deny-listed Characters
- If the character exists in another system env var, we might be able to use the `start` and `length` of that variable to extract the character
	- **Linux Bash** : `/` is at the start of `$PATH`, so we can reference a `/` with `${PATH:0:1}`
		- `printenv | grep "[char]"` will help us find the vars we need (*look on our own linux system*)
	- **Windows CMD** : `%HOMEPATH:~0,-1%` -> `\`
	- **Windows PS** : `$env:HOMEPATH[0]` (*A word in powershell is considered an array so we specify the index, we don't have to put a length*)
		- `Get-ChildItem Env:` gives all PS environment variables

### Bypassing Deny-listed Commands
- Split up the command with characters that are ignored (eg. `whoami` -> `w'h'oa'm'i` - *We can't mix quote types and they must all be balanced*)
	- `\`
	- `$@`
	- `'`
	- `"`