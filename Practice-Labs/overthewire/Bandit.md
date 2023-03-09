---
layout: page
title: Bandit Lab
parent: OverTheWire
grand_parent: Practice Labs
---

# Bandit Practice Game

[Lab Link](https://overthewire.org/wargames/bandit/)

## Level 5

Find a file that has certain properties:
- Human-readable
- 1033 bytes
- not executable

Can use the find command following [this helpful doc](https://linuxize.com/post/how-to-find-files-in-linux-using-the-command-line/)
```
find ./ -type f -size 1033c -perm /666
```

`find ./` - specifies to look in the current dir and any subdirs
`-type f` - specifies to look for files
`-size 1033c` - specifies to look for a size of 1033 bytes
`-perm /666` - specifies to look for a file that at least one group has a permission value of 6 (read-write not exec)

## Level 6

Find a file somewhere on the server that has:
- owner user `bandit7`
- owner group `bandit6`
- 33 bytes

```
find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null -exec cat {} +
```

`-user bandit7 -group bandit6` - specifies the owners
`2>/dev/null` - suppress any errors
`-exec cat {} +` - runs cat on any of the files found

## Level 8

Find unique lines in a file:
```
cat [file] | sort | uniq -u
```

