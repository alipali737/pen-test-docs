```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Ethical and Legal Considerations
- Performing OSINT on a target only via public databases is legal
- Performing ANY scanning or activities that interact with ANY of an organization's systems without explicit written consent in the form of a Scope of Work (including a detailed scope of testing, contract, and rules of engagement) signed by both parties is against the law and could lead to legal and even criminal action being taken against us.
- Real-world experience on [HackerOne](https://hackerone.com/directory/programs) & [Bugcrowd](https://bugcrowd.com/programs) doing bounties, each of which have their own scope and RoE.
- Always get a copy of the contract paperwork and verify it's authenticity & scope (targets) : query anything unexpected (including during the test if additional targets are discovered by accident)
- **Everything should be in writing!** : Document, document, document.
- `Do no harm` and make sure to consider the consequences of that action : gain additional approval if in doubt.

## Penetration Testing Process
![Penetration Testing Process Diagram](penetration-testing-process.png)

### 1. [[1 - Pre-Engagement]]
- Main Commitments, NDAs, goals, scope, limitations, rules of engagement, and related agreements are documented
- Contracts & essential information are shared between testers and client
- Next step is the Information Gathering

### 2. [[2 - Information Gathering]]
- Identify & gain overview of target(s) : Verify they are within scope
- Looking for potential gaps that we could maybe use for a foothold

### 3. [[3 - Vulnerability Assessment]]
- Analyse the results from our *information gathering*, looking for known vulnerabilities in the systems, apps, and versions to discover possible attack vectors.
- Uses manual and automated assessment methods to determine the threat level and susceptibility of a company's asset.

### 4. [[4 - Exploitation]]
- Use the results to test attacks against the potential vectors and execute them to gain initial access

### 5. [[5 - Post-Exploitation]]
- We already have gained access to the exploited machine, ensuring we retain access if modifications and changes are made (Persistence)
- Try to escalate privileges and hunt for sensitive data like credentials or other protected information (pillaging)
- Can be used to demonstrate impact to a client or used as input for lateral movement

### 6. [[6 - Lateral Movement]]
- Movement within the internal network of our target to access additional hosts. Often an iterative process with post-exploitation to reach our goal.

### 7. [[Proof-of-Concept]]
- Document, step-by-step, how we compromised the network or some level of access.
- Aim to show how multiple weaknesses together let us reach our goal.
- Lets them understand how each vulnerability fits in and help prioritise their remediation efforts.
- Ideally we could create automation to help the client reproduce the steps.

### 8. [[Post-Engagement]]
- Prepare deliverable report
- Clean up all traces of our actions
- Review meetings with the client (sometimes presenting to stakeholders)
- Archive our testing data per contractual & company policies

### Example
1. We get all the necessary contract and agreements from the client for a test (including the scope)
2. We gather information on the target and identify potential footholds
3. We use automated scanners and manual investigation to identify potential attack vectors
4. We deploy our attacks to exploit these vectors gaining a level of access to a system
5. We persist this access and attempt to escalate our privileges & pillage for sensitive data
6. We use this position to move throughout the internal network attempting to pillage & gain more privileges, repeating until we achieve our goal
7. We document all the steps taken to achieve our goal and develop a PoC (walkthrough or automation ideally)
8. We prepare and deliver the report, and any presentations & meetings needed. Additionally we archive the testing data and clean up the traces on the system

## Types of Penetration Testing
### External Test
In this test the tester operates from their own host outside of the target network. This focuses on breach points for the target and can often be asked to either be 'stealthy' or a 'hybrid' approach where as the tests become noisier as they progress to test the detection systems.

### Internal Test
This is a 'post-breach' scenario and tests from within the network. Internal tests also allow for testing devices that are not connected to the internet at all.

### Black Box
*Minimal information provided*, only essential information such as IP addresses and domains are provided.

### Grey Box
*Extended information provided*, eg. specific URLs, hostnames, subnets, and the likes

### White Box
*Maximum information provided*, Everything is disclosed and gives us an internal view of the entire structure. This allows for attacks to be prepared from internal information. We may also get detailed configurations, admin credentials, web app source code etc.

### Red Teaming
May include physical testing and social engineering. Can be combined with any of the above. Tends to have a more specific objective than just finding vulnerabilities (eg. access X file on Y server).

### Purple Teaming
Combination of above, however it focuses on working with the defenders to identify gaps.

## Types of Testing Environments
- Network
- IoT
- Hosts
- Server
- Web App
- Cloud
- Mobile
- Source Code
- Security Policies
- API
- Physical Security
- Firewalls
- Thick Clients
- Employees
- IDS/IPS

## Legislation
|**Categories**|**USA**|**Europe**|**UK**|**India**|**China**|
|---|---|---|---|---|---|
|Protecting critical information infrastructure and personal data|[Cybersecurity Information Sharing Act](https://www.cisa.gov/resources-tools/resources/cybersecurity-information-sharing-act-2015-procedures-and-guidance) (`CISA`)|[General Data Protection Regulation](https://gdpr-info.eu/) (`GDPR`)|[Data Protection Act 2018](https://www.legislation.gov.uk/ukpga/2018/12/contents/enacted)|[Information Technology Act 2000](https://www.indiacode.nic.in/bitstream/123456789/13116/1/it_act_2000_updated.pdf)|[Cyber Security Law](https://digichina.stanford.edu/work/translation-cybersecurity-law-of-the-peoples-republic-of-china-effective-june-1-2017/)|
|Criminalizing malicious computer usage and unauthorized access to computer systems|[Computer Fraud and Abuse Act](https://www.justice.gov/jm/jm-9-48000-computer-fraud) (`CFAA`)|[Network and Information Systems Directive](https://www.enisa.europa.eu/topics/cybersecurity-policy/nis-directive-new) (`NISD`)|[Computer Misuse Act 1990](https://www.legislation.gov.uk/ukpga/1990/18/contents)|[Information Technology Act 2000](https://www.indiacode.nic.in/bitstream/123456789/13116/1/it_act_2000_updated.pdf)|[National Security Law](https://www.chinalawtranslate.com/en/2015nsl/)|
|Prohibiting circumventing technological measures to protect copyrighted works|[Digital Millennium Copyright Act](https://www.congress.gov/bill/105th-congress/house-bill/2281) (`DMCA`)|[Cybercrime Convention of the Council of Europe](https://www.europarl.europa.eu/cmsdata/179163/20090225ATT50418EN.pdf)|||[Anti-Terrorism Law](https://web.archive.org/web/20240201044856/http://ni.china-embassy.gov.cn/esp/sgxw/202402/t20240201_11237595.htm)|
|Regulating the interception of electronic communications|[Electronic Communications Privacy Act](https://www.congress.gov/bill/99th-congress/house-bill/4952) (`ECPA`)|[E-Privacy Directive 2002/58/EC](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32002L0058)|[Human Rights Act 1998](https://www.legislation.gov.uk/ukpga/1998/42/contents) (`HRA`)|[Indian Evidence Act of 1872](https://legislative.gov.in/sites/default/files/A1872-01.pdf)||
|Governing the use and disclosure of protected health information|[Health Insurance Portability and Accountability Act](https://aspe.hhs.gov/reports/health-insurance-portability-accountability-act-1996) (`HIPAA`)||[Police and Justice Act 2006](https://www.legislation.gov.uk/ukpga/2006/48/contents)|[Indian Penal Code of 1860](https://legislative.gov.in/sites/default/files/A1860-45.pdf)||
|Regulating the collection of personal information from children|[Children's Online Privacy Protection Act](https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa) (`COPPA`)||[Investigatory Powers Act 2016](https://www.legislation.gov.uk/ukpga/2016/25/contents/enacted) (`IPA`)|||
|A framework for cooperation between countries in investigating and prosecuting cybercrime|||[Regulation of Investigatory Powers Act 2000](https://www.legislation.gov.uk/ukpga/2000/23/contents) (`RIPA`)|||
|Outlining individuals' legal rights and protections regarding their personal data||||[Personal Data Protection Bill 2019](https://www.congress.gov/bill/116th-congress/senate-bill/2889)|[Measures for the Security Assessment of Cross-border Transfer of Personal Information and Important Data](https://www.mayerbrown.com/en/perspectives-events/publications/2022/07/china-s-security-assessments-for-cross-border-data-transfers-effective-september-2022)|
|Outlining individuals' fundamental rights and freedoms|||||[State Council Regulation on the Protection of Critical Information Infrastructure Security](http://english.www.gov.cn/policies/latestreleases/202108/17/content_WS611b8062c6d0df57f98de907.html)|
**Precautionary Measures During Penetration Testing**
- Gain written consent from the owner of the target
- Stay within scope and respect any limitations
- Take measures to prevent causing damage to the systems or networks being tested
- Do not access, use, or disclose any sensitive personal data without permission
- Do not intercept electronic communications without the consent of one of the parties to the communication
- Do not conduct testing on systems covered by HIPAA without prior authorisation