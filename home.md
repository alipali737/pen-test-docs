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
General environment setup can be found [here]({% link /setting-up/setting-up.md %})

----

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
