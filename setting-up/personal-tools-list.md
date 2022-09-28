---
layout: page
title: Personal Tools List
nav_exclude: true
parent: Setting Up
---
# Personal tools to install in my environment
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

A comprehensive documentation for all the tools included in Kali-Linux can be found [here](https://www.kali.org/tools)

## Personal Essential Tools:

{% for tool_category in site.data.personal-tools-list-data.tools %}
### {{ tool_category.category | capitalize }}

{% assign tools = tool_category.items -%}
{% assign tools = tools | sort:"name" -%}

| Tool | Description | Type |
| :---: | :---: | :---: |
{% for tool in tools -%}
| {{ tool.name | capitalize }} | {{ tool.description }} | {{ tool.type }} |
{% endfor -%}
{% endfor %}