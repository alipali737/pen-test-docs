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
| XQuery Injection                        | `'` `;` `--` `/*` */                               |
| Shellcode Injection                     | \x \u %u %n                                        |
| Header Injection                        | \n \r\n \t %0d %0a %09                             |