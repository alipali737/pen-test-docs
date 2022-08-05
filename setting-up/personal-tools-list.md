---
layout: page
title: Personal Tools List
nav_exclude: true
parent: Setting Up
---
# Personal tools to install in my environment

A comprehensive documentation for all the tools included in Kali-Linux can be found [here](https://www.kali.org/tools)

Personal Essential Tools:

{% for tool_category in site.data.personal-tools-list-data.tools %}
### {{ tool_category }}

| Tool | Description | Type |
| --- | --- | --- |
{% for tool in tool_category -%}
| {{ tool.name }} | {{ tool.description }} | {{ tool.type }} |
{% endfor -%}
{% endfor %}