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
