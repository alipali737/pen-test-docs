---
layout: page
title: Home
permalink: /
nav_order: 0
---

# Home Page

This site is a collection of penetration testing and cyber security related materials, guides and resources.

The site is split up into techniques and then individual skills & technologies relating.
{% assign setting_up_page = site.pages | where:"title","Setting Up" -%}
General environment setup can be found [here](https://alipali737.github.io/pen-test-docs/setting-up/setting-up.html)

## Unstructured Labs to Practice on

|  Category   | Link                                                                                                                                                     |
|:-----------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------- |
|   General   | [https://www.vulnhub.com/](https://www.vulnhub.com/)                                                                                                     |
| Web-hacking | [https://www.vulnhub.com/entry/damn-vulnerable-web-application-dvwa-107,43/](https://www.vulnhub.com/entry/damn-vulnerable-web-application-dvwa-107,43/) |
| Web-hacking | [https://dvwa.co.uk/](https://dvwa.co.uk/)                                                                                                               |
| Web-hacking | [http://www.itsecgames.com/](http://www.itsecgames.com/)                                                                                                 |
| Web-hacking | [https://google-gruyere.appspot.com/part1](https://google-gruyere.appspot.com/part1)                                                                     |
|   General   | [https://www.offensive-security.com/labs/individual/](https://www.offensive-security.com/labs/individual/)                                               |
|   General   | [https://www.hackthebox.eu/](https://www.hackthebox.eu/)                                                                                                 |
|   General   | [https://overthewire.org/wargames/](https://overthewire.org/wargames/)                                                                                   |
|   General   | [https://tryhackme.com](https://tryhackme.com)                                                                                                           |
| Web-Hacking | [https://portswigger.net/web-security/dashboard](https://portswigger.net/web-security/dashboard) |                                                                                                                                                          |


----

## Attacks

{% assign all_attack_pages = site.pages | where:"parent","Attacks" -%}
{%- assign all_attack_pages = all_attack_pages | sort:"title" -%}
{% for topic in all_attack_pages %}
- [{{ topic.title }}]({{ topic.url | relative_url }})
{% assign all_topic_children = site.pages | where:"parent",topic.title -%}
{%- assign all_topic_children = all_topic_children | sort:"title" -%}
{%- for detail in all_topic_children %}
    - [{{ detail.title }}]({{ detail.url | relative_url }})
{%- endfor -%}
{%- endfor %}
