```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

> A process of performing detailed searches across the file system and various applications to discover credentials.

**Four Primary Sources for Credentials**
Some examples of places we could look in each source.

| **Files**    | **History** | **Memory**           | **Key-Rings**              |
| ------------ | ----------- | -------------------- | -------------------------- |
| Configs      | Logs        | Cache                | Browser stored credentials |
| Databases    | CLI history | In-memory processing |                            |
| Notes        |             |                      |                            |
| Scripts      |             |                      |                            |
| Source Codes |             |                      |                            |
| Cronjobs     |             |                      |                            |
| SSH Keys     |             |                      |                            |
> Everything in linux is a file. So searching in files across the system can reveal critical insights (credentials, service config, databases etc).

## Configuration Files
Rarely but still possible, some services let you rename the config files, meaning that just searching for extensions isn't always all-encompassing.
```sh
# Find all files witn the any of the extensions, skipping the dirs at the end
$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Search for key words in any files matching the criteria
$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

## Databases
The same search ideas can be applied to database files.
```shell
$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

## Notes
Searching for notes is harder as they can be stored anywhere with any name. Often they will not have an extension or may include a `.txt` extension.
```sh
# find all files in the home/* dirs, that either have .txt or no extension (== '*.txt' or != '*.*')
$ find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

## Scripts
