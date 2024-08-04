---
layout: page
title: Personal Web App Testing Approach
parent: Methodologies
grand_parent: Testing
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

## Pre-Engagement
Legal contract between tester & client, including:
- NDAs
- Goals / Objectives / Intentions
- Scope (Allowed targets)
- Time estimation
- Rules of engagement (Can and Cant's)

This is incredibly important and has to be there before any tests are even considered. This protects both parties so it must be in-depth!

## Information Gathering
- Web infrastructure
- Software applications used
- Hardware used

**Passive Reconnaissance:** Gaining intelligence without interacting directly with the target. Using OSINT information about the target might be discovered.
- Google Dorking
  - `site:<x>`
  - `inurl:<x>`
  - `ext:<x>` or `filetype:<x>`
  - `cache:<url>` or archive.org
  - `after:<timestamp>`
  - `before:<timestamp>`

**Active Reconnaissance:** Directly interacting with the target to gain deeper understanding and information
- Nmap : Network mapping & probing tool
- Nessus : Vuln scanner
- OpenVAS : Vuln scanner
- Nikto : Vuln scanner