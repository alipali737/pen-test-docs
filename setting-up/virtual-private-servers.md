---
layout: page
title: Virtual Private Servers
parent: Setting Up
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

A VPS is an isolated environment created on a physical server using virtualization technology. It can also be refered to as a **V**irtual **D**edicated **S**erver (**VDS**). They are an affordible model for offering a comprehensive range of functions at manageable prices.

**VPS Common use cases:**
- Webserver
- Development server
- Pentesting
- Proxy server
- VPN
- Mail server
- Test server
- Gaming server
- DNS server
- Code repo

## VPS Setup
1. Install a new OS to the VPS (recommended `Ubuntu`, `Debian` etc)
2. SSH into the server
3. Make sure that it is updated with:
{% highlight shell %}
$ sudo apt update -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y
{% endhighlight %}
4. Install any tools you might need:
{% highlight shell %}
$ sudo apt install net-tools
$ sudo apt install xrdp
{% endhighlight %}
5. Make any users you need to, ideally a sudo and one without admin perms
6. Setup any SSH keys needed (for windows you can use [this guide](https://www.chrisjhart.com/Windows-10-ssh-copy-id/) to copy the key to the server)

## VPS Hardening
The purpose of hardening is to lock down our VPS by limiting the access. We want to ensure that the only access is SSH and disable all other services. We will reduce the attack vectors to a minimum and provide only one possible access to the VPS, which we will secure as best as we can.

We should also keep in mind not to store sensitive data on the VPS and always follow the principle that someone could gain access sooner or later. You should harden the VPS depending on its use and who needs access.

There are many ways to harden it, these can include, but not limited to:
- Install Fail2ban
- Working only with SSH keys
- Reduce Idle timeout interval
- Disable passwords
- Disable X11 Forwarding
- Use a different (non default) port
- Limit users' SSH access
- Disable root logins
- Use SSH proto 2
- Enable 2FA Authentication for SSH

`It is highly recommended to try these settings and precautions first in a local VM we have created before making these settings on a VPS`
