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
> Very often we need to make sure to URL encode queries as `/` becomes `%2f`.
#### Absolute Path
Sometimes an **absolute path** will just work: `/etc/password`. 
#### Path Traversal
However, it could be getting prefixed with a path for instance eg. 
```php
include("./pages/" . $_GET["lang"]);
```
This would mean we end up with `./pages//etc/passwd`, we can use path traversal here instead: `../../../../etc/passwd`.
> As `../` at root doesn't actually break anything, we can add loads and later find out the minimum needed when we write the report.
#### Filename Prefixed
```php
include("lang_" . $_GET["lang"]);
```
We can avoid this by prefixing our input with a `/` so its `/../../../../etc/password`. This will make it think `lang_/` is a directory instead now and then we will bypass it with the `../`'s.
> This isn't greatly reliable however.
#### Extension Suffixed
```php
include($_GET["lang"] . ".php");
```
// TODO:

### Second-Order Attacks
Another common method, but slightly more advanced is a *Second-Order Attack*. This is where a web application insecurely pulls files from a back-end server based on user-controlled parameters. For example, a web app could get a user's profile picture from `/profile/$username/avatar.png`. The user themselves doesn't control the actual query but they do control their username, thus if their username was `../../../etc/password`, this would become `/profile/../../../etc/password/avatar.png`. This in itself isn't isn't the full attack but could be a leading factor.
> Developers can often trust values coming from their database but if those values are user-controlled then they can't be trusted.

### Basic Bypasses
#### Non-Recursive Path Traversal Filters
A very common protection is to replace `../` with a empty string.
```php
$lang = str_replace('../', '', $_GET['lang']);
```
As this isn't recursive, we can bypass this by making it form the `../` for us using `....//`.
We can also use `..././` or `....\/`, these will both have the same result. Adding more `/`'s (`....////`) or escaping the `/` (`....\/`) can also sometimes bypass these filters.
#### Encoding
We can sometimes get away with URL encoding the entire string:
```
../../../etc/passwd = %2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%6f%72%64
```
> Burp Decoder can do this easily. We can also double encode this string to bypass other filters.
#### Approved Paths
Some applications with use regex to ensure an input is only within approved paths:
```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['lang'])) {
	include($_GET['lang']);
} else {
	echo 'Illegal path specified';
}
```
We must first examine the application's normal behaviour to understand what paths are approved, then we can use an approved path first alongside `../` to escape it afterwards: `/languages/../../../../etc/passwd`.
