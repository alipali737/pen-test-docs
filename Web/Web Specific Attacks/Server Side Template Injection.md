```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
SSTI is when user input is accepted as a value in a template that is used in the webpage's response. This means an attacker can submit native template syntax to inject a malicious payload into a template, which is then executed server-side.

This can pose the possibility for RCE for an attacker.

## Detecting SSTI
Using a fuzzing template such as: 
```
${{<%[%'"}}%\
```
you can detect a template expression being used. If an exception is raised, we know that the template is being executed.

### Identify the Context
#### Plaintext Context
It is important to understand the context of how the template is being interpreted. Often SSTI is mistaken for a simple XSS where text is rendered in. But in SSTI, math operations can be used to identify it:
```
${7*7}
```
> If this template is being evaluated, we would expect 49 to be output.

This method is where the user input is being directly added to a string eg.
```js
render('Hello ' + username)

// http://vulnerable-website.com/?username=${7*7}
```

#### Code Context
The other type of context is where the user input is being used within a template eg.
```js
greeting = getQueryParameter('greeting')
engine.render("Hello {{"+greeting+"}}", data)

// http://vulnerable-website.com/?greeting=data.username
```
This means that we need to *identify we are in a template*, and then attempt to *break out of the template*.

This context is easily missed because it doesn't result in an obvious XSS. First we need to *establish that the parameter doesn't contain a direct XSS* by injecting HTML
```http
http://vulnerable-website.com/?greeting=data.username<tag>
```
> We want this to NOT be an XSS, eg. we are looking for a blank entry, encoded tags, or an error ideally.

Next step is to try to break out of the template:
```http
http://vulnerable-website.com/?greeting=data.username}}<tag>
```
> If this is a blank output or an error, we have likely used the wrong syntax for the template engine. If no syntax is valid then SSTI is not present.
> Alternatively, if we get a normal output along with the HTML, then SSTI is likely possible.

## Identify the Template Engine
We can use specifically crafted payloads to determine what engine is being used. *Often an error message will give it away anyways*. A decision tree like this for example:
![[SSTI tree.png]]
Can be really useful to determine the engine.
> eg. `{{7*'7'}}` in Twig will result in `49` but will be `7777777` in Jinja2
> [PayloadAllTheThings SSTI cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md?ref=sec.stealthcopter.com)
