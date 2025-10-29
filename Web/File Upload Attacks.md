```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Bypassing Filters and Validation
### Client-side validation
- This can be bypassed by intercepting the request and sending it directly rather than via the website (eg. burp)

### File Extension Deny List
- In windows, file extensions are case insensitive
- Fuzz for if any extension variations are accepted ( [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst), [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP), and common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt))
### File Extension Allow List
- Fuzzing extensions is still useful to see what extensions are available, it may also show if any extensions are able to be bypassed 
- Use double stacked extensions, it may be that the filter only check if it contains, not ends with
- Character injection (these have specific ways to be used however but most lists will include it correctly)
	- `%20`
	- `%0a`
	- `%00`
	- `%0d0a`
	- `/`
	- `.\`
	- `.`
	- `…`
	- `:`
This script will generate all permutations of character injection using the above
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```
