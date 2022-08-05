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
General environment setup can be found [here]({{ setting_up_page.url | relative_url }})

----

{% assign all_attack_pages = site.pages | where:"parent","Attacks" -%}
{% for topic in all_attack_pages %}
- [{{ topic.title }}]({{ topic.url | relative_url }})
{% assign all_topic_children = site.pages | where:"parent",topic.title -%}
{%- for detail in all_topic_children -%}
    - [{{ detail.title }}]({{ detail.url | relative_url }})
{%- endfor -%}
{%- endfor %}
