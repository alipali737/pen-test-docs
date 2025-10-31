```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
[HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering) is when unexpected methods are sent in requests to the server, which cause functionality to break or unexpected code paths to be taken (eg. *bypassing authorisation*).
> https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/http-request-methods.txt - useful list to iterate through to check for strange behaviours

This attack is only possible if insecure coding practices are occur. It may be that for certain pages, authentication is required and request methods are configured:
```xml
<Limit GET POST>
	Require valid-user
</Limit>
```
This however would still allow a user to submit a `HEAD` (*for example*) request and bypass the requirement for authentication. This vulnerability can be introduced in many ways but most commonly its when using filters that apply to specific methods only.

This technique can also be utilised to sometimes bypass other security controls that might be preventing other exploits (eg. an SQLi filter may only be applied on `GET` requests)
## Exploitation
1. First understand what directory level the authentication is required at, eg. `/admin/reset.php` has two potential levels the auth could be enforced (`/admin`, or `/reset.php`).
2. Fuzz for what methods are blocked and what are not (*if working on a prod system we do need to be careful here when using methods like `DELETE`*)
> Burp also has a `change request method` setting on a request in the right-click menu. This will swap between `GET` and `POST`.

## Prevention
- Don't restrict requirements like authentication to a particular HTTP method
- Use a Deny-All Except policy inst