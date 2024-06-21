---
layout: page
title: Session Security
parent: Web
grand_parent: Knowledge
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
## Cookie Session Management

Cookies can be used to automatically send a session ID on every HTTP request from a client. The `localStorage` or `sessionStorage` could also be used but they adhere to different behaviours:

| | Cookies | localStorage | sessionStorage |
|-|-|-|-|
| Read by Server | Yes | No | No |
| Capacity | 4KB / Domain | 10 MB / Domain | 5 MB / Domain |
| Expiry | Custom | Never or On Manual Deletion in Browser | When Session Tab Closes |
| Browser Compat | HTML4, HTML5 | HTML5 | HTML5 |
| Access From | Any Window | Any Window | Same Tab |

As the `localStorage` and the `sessionStorage` can only be accessed via Javascript directly, they are better suited for storing other information rather than `sessionIDs`.

### Securing Cookies

In order to prevent a series of common vulnerabilities eg. Session Hijacking, XSS, CSRF. Cookies need to be secured.

#### Session Expiry

Cookies can be set to expire after a certain period. The shorter a session is, the less time an attacker has to hijack it. This is usually done by setting and expiry on the session cookie but **should** also include automatic session expiry on the backend too.

It can be set with `Expires=<date>` or `Max-Age=<number>` where Max-Age takes priority

Some sites will expire a session after a certain time regardless of user activity, some will automatically expire after a certain period of inactivity.

#### Session ID Values

Like passwords, the longer and more complex a session ID the better. OWASP specifies it should be at least 128 bits long. It should also no contain personally identifyin information or follow a predefined pattern.

#### Secure Cookie Attributes

Cookies can be configured with the following attributes:
- [Secure](https://owasp.org/www-community/controls/SecureCookieAttribute)
  - This will prevent the cookie from being sent over an unencrypted channel (eg. Has to be using HTTPS)
- [HttpOnly](https://owasp.org/www-community/HttpOnly)
  - This means the cookie cannot be accessed through a client-side script, it will only be available via a HTTP(S) request
- [SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
  - This controls whether a cookie is sent with cross-site requests, providing some protection against CSRF
  - `Strict` : Only send for requests on the site that set the cookie
  - `Lax` : (Default) Not sent on cross-site requests, apart from if it is to the origin site from an external site
  - `None` : The cookie is sent on both cross-site and same-site requests, the `Secure` attribute must be set for this.

## Security-Related HTTP Headers

HTTP Headers inform browsers how to behave if a website subscribes to a certain security policy. They can protect both the user and the web application, preventing attacks like Cross-Site Scripting (XSS). Security headers will also increase the SEO of the website as its trustworthiness increases.

TODO: Write sections on
- `expect-ct`
- `report-uri`
- `referrer-policy`
- `x-download-options`
- `x-permitted-cross-domain-policies`
- `x-xss-protection`

https://owasp.org/www-project-secure-headers/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security

[Check what security headers are on a website](https://securityheaders.com/)

### Strict-Transport-Security

This header specifies that the site is only available through HTTPS. Enforcing encryption rather than plaint HTTP communication. This can help prevent Man-In-The-Middle attacks.

```HTTP
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

- `max-age` tells the browser to remember this for 1 year, reducing redirect responses to the HTTPS version of the site in future.
- `includeSubDomains` tells the browser that the current site + any sub-domains are all HTTPS-only.

[MDN Web Doc](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)

### Content-Security-Policy

This defines an allow-list of sources of content. This restricts the assets that the browser can load while on the website. This can prevent XSS attacks and packet sniffing attacks. A common use is to ensure that all content is loaded with HTTPS.

```HTTP
Content-Security-Policy: <policy>
```

A policy is described using a series of policy directives, each of which describes the policy for a certain resource type or policy area.

A policy should always include a [`default-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src) as a fallback for any resource types that don't have a specific CSP.

A full list of fetch directives can be found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#fetch_directives).

Policies can be tested by setting:
```HTTP
Content-Security-Policy-Report-Only: <policy>
```

#### Example Use Cases

1. All content to come from the site's own origin (Excludes sub-domains):
```HTTP
Content-Security-Policy: default-src 'self'
```

2. Allow content from trusted domain and all its subdomains (doesn't have to be the same domain the CSP is on):
```HTTP
Content-Security-Policy: default-src 'self' example.com *.example.com
```

3. Allow images from anywhere, but restrict audio & video to trusted providers, and all scripts only to a specific server:
```HTTP
Content-Security-Policy: default-src 'self'; img-src *; media-src trusted.org trusted.net; script-src userscripts.example.com=
```

4. Ensure all content is loaded from a single domain using TLS (HTTPS):
```HTTP
Content-Security-Policy: default-src https://somebank.example.com
```

[MDN Web Doc](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

### X-Frame-Options

This controls whether the website can be displayed in an `<iframe>` tag. This helps to prevent clickjacking (where an attacker can display your website in an iframe and embed secret hidden frames over the top to cause the victim to click on malicious links)

```HTTP
X-Frame-Options: <Option>
```

- `DENY` prevents an iframe being used on anysite
- `SAMEORIGIN` only allows this page to be put into an iframe within the site's domain
- `ALLOW-FROM <domain>` allows a list of sites to put the current content into an iframe

### X-Content-Type-Options

This can be used to indicate that the [MIME types](#mime-types) advertised in the `Content-Type` header should be followed and not changed. This can avoid [MIME Type Sniffing](#mime-type-sniffing) by saying that the MIME types are deliberately configured.

```HTTP
Content-Type: text/html

X-Content-Type-Options: nosniff
```
> `nosniff` blocks a request if the request destination is type `style` and the MIME type is not `text/css`, or of type `script` and the MIME type is not a JavaScript MIME type.

This feature only applies to request destinations of `script` and `style`. However, it also enables Cross-Origin Read Blocking (CORB) protection for HTML, TXT, JSON and XML files.

#### MIME Types

A **Media type** describes the nature and format of the document, file, or assortment of bytes.
> A browser will use the MIME type, not the file extension, to determine how to process the URL.

The MIME Type can be set using the `Content-Type` header using the `type/subtype` format (eg. `text/html`, `image/png`, `audio/mp3`).

#### MIME Type Sniffing

When no MIME type is set, or in certain cases where browsers believe they are incorrect, browsers may perform MIME Sniffing. Guessing the correct MIME type by looking at the bytes of the resource.

Every browser peforms MIME Sniffing differently and under different conditions (eg. Safari will look at the file extension). However, there are security concerns as some MIME types can represent executable content. This sniffing can be prevented by sending the `X-Content-Type-Options: nosniff` header.

### Referrer-Policy

The policy controls how much referrer information is included with requests. There are privacy and security concerns associated with the `referrer` HTTP request header. The `referrer` header contains the address from which the request originated (eg. the page a link was clicked to create the current request). This can have security issues as it can leak things like password reset URLs etc.

A referrer could look like: `https://example.com/page.html?name=test`. It contains an `protocol`://`origin`/`path`?`querystring`

```HTTP
Referrer-Policy: <policy>
```
- `no-referrer` means the referrer heading will be omited
- `no-referrer-when-downgrade` specifies that the referrer can be send if the protocol security level stays the same or improves (eg. HTTP -> HTTPS, HTTPS -> HTTPS, HTTP -> HTTP) but omit if it downgrades (eg. HTTPS -> HTTP)
- `origin` only send the origin, not the full path & querystring.
- `same-origin` only sends the full referrer on same-origin requests.
- `origin-when-cross-origin` only sends the origin for cross-origin requests otherwise acts the same as `same-origin`.
- `strict-origin` only sends the origin when the security protocol stays the same (HTTPS -> HTTPS) but doesn't send the header to less secure destinations (HTTPS -> HTTP).
- *(Default)* `strict-origin-when-cross-origin` sends the full referrer for same-origin requests but acts like `strict-origin` for cross-origin requests.

The `Referrer-Policy` can also be set in the HTML of the page:
```HTML
<meta name="referrer" content="origin">

<a href="http://example.com" referrerpolicy="origin">...</a>
<a href="http://example.com" rel="noreferrer">...</a>
```