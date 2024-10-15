```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Payment Card Industry Data Security Standard (PCI DSS)
The [Payment Card Industry Data Security Standard (PCI DSS)](https://www.pcisecuritystandards.org/pci_security/), although not a government standard, dictates the requirements for storing, processing, or transmitting cardholder data. This would include any banks or online stores that handle their own payment solutions (eg. Amazon).

Any credit card data that is processed or transmitted must be done in a *Cardholder Data Environment* (*CDE*). The CDE must be segmented from normal assets to further protect it in the case of the main network being compromised.

**PCI DSS GOALS**:
- Build and maintain a secure network
- Protect cardholder data
- Maintain a vulnerability management program
- Implement strong access control measures
- Regularly monitor and test networks
- Maintain an information security policy

## Health Insurance Portability and Accountability Act (HIPAA)
The [Health Insurance Portability and Accountability Act](https://www.hhs.gov/programs/hipaa/index.html) is to protect US patients' data. Although not necessarily requiring vulnerability assessments or scans, risk assessments must be performed to maintain HIPAA accreditation.

## Federal Information Security Management Act (FISMA)
The [Federal Information Security Management Act (FISMA)](https://www.cisa.gov/federal-information-security-modernization-act) is a set of standards and guidelines used to safeguard government operations and information. The act requires organisations to provide documentation and proof of a vulnerability management program to maintain proper system availability, integrity, and confidentiality.

## ISO 27001
[ISO 27001](https://www.iso.org/isoiec-27001-information-security.html) is an international standard that requires organisations to perform quarterly external and internal scans.

## Penetration Testing Execution Standard (PTES)
[Penetration Testing Execution Standard](http://www.pentest-standard.org/index.php/Main_Page) covers all types of penetration testing. Outlining phases of a pentest and how they should be conducted. These sections are:
- Pre-engagement Interactions
- Intelligence Gathering
- Threat Modelling
- Vulnerability Analysis
- Exploitation
- Post Exploitation
- Reporting

## Open Source Security Testing Methodology Manual (OSSTMM)
[OSSTMM](https://www.isecom.org/OSSTMM.3.pdf) is another set of guidelines for pentesters. It is often used alongside other standards. It is divided into five channels for five different areas of pentesting:
- Human Security (human beings are subject to social engineering exploits)
- Physical Security
- Wireless Communications (including but not limited to technologies like WIFI and Bluetooth)
- Telecommunications
- Data Networks

## National Institute of Standards and Technology (NIST)
