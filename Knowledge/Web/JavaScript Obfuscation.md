```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Obfuscation 
*(ob-fus-cation)*
Re-writes human readable code into a more difficult to understand but still technically identical code (can cost performance). Can be used to hide malicious code from IDS & IPS. 

### Tools
[BeautifyTools](http://beautifytools.com/javascript-obfuscator.php) - this tool uses packing : It primarily uses dictionaries to substitute symbols and words. Its good but still reveals strings in the application so its less secure.

[obfuscator.io](https://obfuscator.io/) - a more advanced obfuscator with many options to tweak it (including string to base64)

[JSFuck](http://www.jsfuck.com/) - utilises symbols, can have major performance effects.

 [JJ Encode](https://utf-8.jp/public/jjencode.html) or [AA Encode](https://utf-8.jp/public/aaencode.html) can be used for explicit purposes (eg. bypassing web filters) but will cause significant performance reductions.
### Minifying
Makes the code shorter by removing whitespace and new lines, outputting a single (very long) line of code. [javascript-minifier](https://javascript-minifier.com/)

Can be undone by *Beautifying* the code (eg. Pretty Printing) and can often be done in-browser. Or through tools like: [Prettier](https://prettier.io/playground/) or [Beautifier](https://beautifier.io/).
## Deobfuscation
For something that has been *packed*, tools like [UnPacker](https://matthewfl.com/unPacker.html) can be very helpful. Alternatively, if you can identify the *return* statement, you can `console.log()` it instead of executing it and it will return a more readable version of the unpacked code.

Text encoding is often used in obfuscation and can be spotted and decoded with a variety of tools. Techniques such as Base64 *(only alphanumeric and `=` for padding as they need to be in multiples of 4. Decoded with `base64 -d`)*, Hex *(0-9 a-f, decoded with `xxd -p -r`)*, or sometimes Ceaser/Rot13 are used which shift the charact

