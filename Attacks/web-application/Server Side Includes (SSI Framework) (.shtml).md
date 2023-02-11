---
layout: page
title: Directory Enumeration Attack
parent: Web Application
grand_parent: Attacks
---
# {{ page.title }}
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

SSI is a simple interpreted **server-side scripting language**. Most useful for including the contents of one or more files into a webpage on a webser, using its `#includes` directive.

#### Supported on:
- Apache
- LiteSpeed
- nginx
- IIS
- W3C's Jigsaw

#### Uses the folloing extensions (by default):
- `.shtml`
- `.stm`
- `.shtm`

Follows a simple syntax of:
```SSI
<!--#directive paramter=value parameter=value -->

Example:
<!--#include virtual="../quote.txt" -->
```

## Directives
### Common
| Directive               | Parameters                  | Description                                                                                                                                                                                                                              | Example                                  |
| ----------------------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `include`               | file or virtual             | Include another document in this one; `virtual` handles any path as if part of the url; `file` handles any path as if part of the underlying filesystem; `file` cannot use absolute paths or `../`; `virtual` is recommended over `file` | `<!--#include virtual="menu.cgi" -->`    |
| `exec`                  | cgi or cmd                  | Executes a program, script, or shell command; `cmd` specifies a server-side command; `cgi` specifies a path to a [CGI](https://en.wikipedia.org/wiki/Common_Gateway_Interface) script                                                    | `<!--#exec cmd="ls -la" -->`             |
| `echo`                  | var                         | Displays the contents of a [HTTP env var](https://en.wikipedia.org/wiki/Environment_variable)                                                                                                                                            | `<!--#echo var="REMOTE_ADDR" -->`        |
| `config`                | timefmt, sizefmt, or errmsg | Configures the display formats for the date, time, filesize, and error message (returned when an SSI command fails)                                                                                                                      | `<!--#config timefmt="%y %m %d" -->`     |
| `flast mod` and `fsize` | file or virtual             | Displays date when the specified file was last modified or its size                                                                                                                                                                      | `<!--#flastmod virtual="index.html" -->` |
