```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Local File Inclusion
This is most common within templating engines (eg. `/index.php?page=about`), these engines allow static content like a header and footer to be centralised and then the main content is just dynamically templated in. Some key code examples to investigate for possible LFI:
### Code Examples
#### PHP
```PHP
include();
include_once();
require();
require_once();
file_get_contents();
```
#### NodeJS
```js
readFile();
render();
```
#### Java
```jsp
<jsp:include file ... />
<c:import url ... />
```
#### .Net
```cs
Response.WriteFile()
@Html.Partial()
@Html.RemotePartial()
#include file=...
```

Some of these methods not only read the file but also execute it, some even read remote URLs so there is further abuse we can cause:

|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|✅|✅|✅|
|`require()`/`require_once()`|✅|✅|❌|
|`file_get_contents()`|✅|❌|✅|
|`fopen()`/`file()`|✅|❌|❌|
|**NodeJS**||||
|`fs.readFile()`|✅|❌|❌|
|`fs.sendFile()`|✅|❌|❌|
|`res.render()`|✅|✅|❌|
|**Java**||||
|`include`|✅|❌|❌|
|`import`|✅|✅|✅|
|**.NET**||||
|`@Html.Partial()`|✅|❌|❌|
|`@Html.RemotePartial()`|✅|❌|✅|
|`Response.WriteFile()`|✅|❌|❌|
|`include`|✅|✅|✅|
### Basic LFI
Sometimes an **absolute path** will just work: `/etc/password`. However, it could be getting prefixed with a path for instance eg. `include("./pages/" . $_GET[lang]);`. This would mean we end up with `./pages//etc/passwd`, we can use path traversal here instead: `../../../../etc/passwd`.
> As `../` at root doesn't actually break anything, we can add loads and later find out the