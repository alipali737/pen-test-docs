---
layout: page
title: OhSINT CTF
parent: tryhackme
grand_parent: Practice Labs
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
Lab link: https://tryhackme.com/room/ohsint#
Difficulty: Easy

This lab is all about OSINT. We are only provided with an image:
![[WindowsXP.jpg]]

Running it through `exiftool` (which organises all the metadata from within the file) it reveals some important information:
![[Image-metadata-exiftools_16_10_2023_15_48_00.png]]
The standout details are the GPS cords & **the copyright**.
When we search that name we get a few interesting results...
![[google-search-owoodflint.jpg]]

When we look at the twitter we are granted our first answer.
![[owoodflint-twitter.jpg]]

The 2nd tweet is also interesting, thinking that question 2 is: `What is the SSID of the WAP he connected to?`

By using [wigle.net](https://wigle.net) we can look up the location of that BSSID. Eventually finding it was located in **London**. Giving us answer 2 & 3 (`What is the SSID of the WAP?`) which is **UnileverWIFI** 
![[Pasted image 20231016161147.png]]

Q4 & Q5: `What is their email? And what website is it available on?` are more simple ones, as it is listed on their github project [people_finder](https://github.com/OWoodfl1nt/people_finder).

Q6 asks where he has gone on holiday to: When we look on [his website](https://oliverwoodflint.wordpress.com/author/owoodflint/) you can see its **New York**. They also seem to have accidently revealed their password on this website too, which answers Q7: **pennYDr0pper.!**

