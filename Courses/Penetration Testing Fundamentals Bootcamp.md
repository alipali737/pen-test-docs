
# Penetration Testing Fundamentals Bootcamp
{: .no_toc}

O'Reilly course that teaches the early fundamentals of Penetration Testing.

[Course Link](https://learning.oreilly.com/live-events/penetration-testing-fundamentals-bootcamp/0636920074907/0636920074906/)

### Covering:
{: .no_toc}
- How to maintain your own pentesting lab environment
- Which tools, operating systems, and virtualization you need to succeed
- Which of the 38 penetration testing certifications you want and how to get it
- The five technical phases of penetration testing
- How to keep your job and stay out of jail as a tester
- What it takes to do the job of an ethical hacker
- How to perform a penetration test
- How to build foundational skills in penetration testing

### Table of Contents
{: .no_toc .text-delta}

* TOC
{:toc}

---

## Day 1

### Recon of target website 
Website: [blocked on IBM network](expsec.us)
Goal: Obtain user accounts

Need to build a userlist:
- Can build a userlist from the 

1. Installed `seclists` on Kali to obtain password lists

1. First check `ifconfig`:
    - Write down the address of the attacking system (kali)
    - Write down the addresses of the victim systems 
    - Test they can all communicate (Ping, nmap etc) (win2k8 server doesn't respond to ping)

- Attk: eth0: 192.168.100.4 netmask 255.255.255.0
- Victim (ub1404): eth0: 192.168.100.5 mask 255.255.255.0

Spend time creating ISO image library:
- create templates of these images so you can put together a sample to test against during a pentest before you test against the real target system

PenTest VM Setup Process:
[Find out PTest target system details]
                |
                v
[Create replica box to test locally on]
                |
                v
[Test exploits against replica box (what works, what doesn't, false positives)]
                |
                v
[Try tests against real target]

#### [Useful Steps and Process for conducting the PenTest](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)

Create an artifact sheet to collect information as you go

Test the website:
- Collect site information
- Can use [netcraft](https://sitereport.netcraft.com/)
- Could use Nmap OS detection only `nmap --osscan-limit`
- MAKE SURE TO CONFIRM THE INFORMATION!!!

OSINT:
- Collect information regarding the asset
- eg. indirect via job postings regarding the company?

Pen Testing is all about testing **All of the possible entries** not exploiting just a single one

#### Some useful tools:
##### Scope
- Contract

##### Recon
- Google
- Maltego = local GUI (PAID)
- Shodan (PAID)

##### Scanning
- Nmap
- OpenVAS = local GUI (when internal to organisation, for patch management)

##### Exploitation
- Metasploit

##### Maintain access
- Metasploit

##### Covering tracks (for fighting blue team or defences)
- Distractions (DoS)
- Disable logging
- Clear logs
- IMPORTANT: leaves vuln to actual attackers during, make sure to record every action made in PTest

##### Report
- Artifacts = Packets / Screenshots
- Encrypted PDF

### Further videos:
- [Overview to PTesting](https://learning.oreilly.com/videos/certified-ethical-hacker/9780996619158/9780996619158-CEH11_01_01/)
- [Footprinting and Recon](https://learning.oreilly.com/videos/certified-ethical-hacker/9780996619158/9780996619158-CEH11_02_01/)
- [Enumeration](https://learning.oreilly.com/videos/certified-ethical-hacker/9780996619158/9780996619158-CEH11_04_01/)
- [Vulnerability Analysis](https://learning.oreilly.com/videos/certified-ethical-hacker/9780996619158/9780996619158-CEH11_05_01/)



#### Questions:
- Who is the company?
    - Exp Sec
- What is their website?
    - [blocked on IBM network](expsec.us)
- What tools do they tell us about?
    - Draft job listing mentions:
        - Windows Server 2008
        - Oracle **Glassfish** Enterprise Server
        - Jenkins
        - ManageEngine Desktop Central Server
        - ElasticSearch
        - **MySQL**
        - **PHPMyAdmin**
        - **Wordpress**
- Where can we get public login information?
    - Company Email Directory page
    - Emails are often associated with logins
- How can we mangle that?

#### Notes:
- Site in running as a wordpress site
- They are starwars geeks

### Careers in Pen Testing (Cyber Defense Analyst)
- 38 pen testing certifications
- [229 Cyber Security Certifications](https://docs.google.com/spreadsheets/d/1Bk35IoIglqcPtcMLQUX4CLwaXgh8rdvw4UrbHqGJlE8/edit#gid=1452594778)
- [All Security Certifications](https://pauljerimy.com/security-certification-roadmap/)
- [Cyber Security Pathways & Job Details](https://niccs.cisa.gov/workforce-development/cyber-career-pathways-tool)