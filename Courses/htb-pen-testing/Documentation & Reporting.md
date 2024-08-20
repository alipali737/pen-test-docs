```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## The Snapshot
An overview should be included talking about:
- what type of work was performed
- who performed it
- what IP addresses were used in the testing
- any special considerations (eg. was it performed over a VPN or within the network)
- period it was performed
- any changes to in-scope systems and resultant vulnerabilities would not be captured in the report

## Directory Format
My personal notes directory format should include:
- *Evidence* : contains all information about what happened, what was found, any notes
	- *Findings* : Vulnerabilities found and write-ups (sub-folder for each)
	- *Logging output* : raw logs from Tmux, Metasploit etc that doesn't belong in scans - [[#Logging]]
	- *Misc files* : any misc files that were involved in the test (Webshells, payloads, scripts, any other files generated)
	- *Notes* : personal notes throughout the test
		1. *Administrative Information* : Useful admin information (contacts, unique objectives/flags, RoE, **To-Do list**)
		2. *Scoping information* : Any scoping information that is important (eg. IPs, URLs, any provided credentials for apps, VPNs, AD etc)
		3. *Activity Log* : high-level tracking of everything you did during an assessment for event correlation
		4. *Payload Log* : tracking the payloads being used (inc a file hash for anything uploaded and its location). Also include any payloads used, which hosts, paths, whether it was cleaned up or not.
		5. *OSINT* : a section to track any useful OSINT information if applicable, gathered (links, content, descriptions etc)
		6. *Credentials* : all compromised credentials & secrets found
		7. *Web Application Research* : Any web applications found through various methods (forced-browsing, common web port scans, Aquatone or EyeWitness tools can screenshot applications, common/default credentials tried)
		8. *Vulnerability Scan Research* : Anything researched & tried with vuln scans
		9. *Service Enumeration Research* : Which services investigated, failed exploitation attempts, promising vulnerabilities/misconfigurations etc
		10. *AD Enumeration Research* : Step-by-step what Active Directory enumeration has been performed, any areas of interest
		11. *Attack Path* : Outline the entire path to gain a foothold for external tests / compromise one or more hosts (or AD Domain) for internal tests. Outline as close as possible (outputs, screenshots etc)
		12. *Findings* : personal notes regarding the findings (helps for organising report later)
	- *OSINT* : any OSINT outputs from tools that don't fit well into notes 
	- *Scans* : scan logs & results
		- *Vulnerability Scans* : export files from vuln scanner (if possible) for archival
		- *Service enumeration* : export files from tools used to enumerate services in target environment
		- *Web* : Export files from tools like ZAP, Burp state files, EyeWitness, Aquatone etc
		- *AD Enumeration* : JSON files from BloodHound, CSVs from PowerView or ADRecon, Ping Castle data, Snaffler logs, CrackMapExec logs, data from Impacket tools etc
	- *Wireless* : Output of any wireless testing tools
- *Deliverables* : anything that is going to the client
- *Admin* : any administration documents regarding the test (scope of work, kick off notes, status reports, vulnerability notifications etc)
- *Retests* : Replicate file structure in here for any retesting done

## Logging
It is essential to **log all scans & attack attempts (keeping raw outputs)**. Can be useful to ensure we didn't miss something & answering questions / report writing.

Make sure to use **Tmux Logging**, this saves all content of a Tmux pane to a log file. This is super helpful for proving what tests were conducted and what the client is protected against if we have little to no findings to report.

1. Clone the [Tmux Plugin Manager](https://github.com/tmux-plugins/tpm) repo
`git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm`
2. Create a `.tmux.conf` in the home dir
3. Add the following content
```
set -g history-limit 100000

# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
```
4. Start a new tmux session `tmux new -s setup`
5. Press `[Ctrl] + [B]` then `[Shift] + [I]` to install the plugin
6. Start the logging with `[Ctrl] + [B]` and `[Shift] + [P]`
7. Stop the logging with `[Shift] + [P]` or `exit` (kills the session)

If you forget to start the logger, `[Ctrl] + [B]` then `[Alt] + [Shift] + [P]` captures the entire pane.

`[Ctrl] + [B]` & `[Alt] + [P]` captures a screenshot of the focused pane/window (useful when having multiple open)

## Account Creation / System Modification
Any creations or modifications should be tracked in case we cannot revert them afterwards:
- IP of host(s)/Hostname(s) where changes are made
- Timestamp of changes
- Description of change
- Location on the host(s) where the change was made
- Name of the application or service that was tampered with
- Name of the account (if you created one) and possibly the password if you need to surrender it
Make sure you have client approval before any changes are made that could affect system stability or availability. Usually determined when to notify client during the kickoff.

## Evidence
Make sure its clear for people to reproduce and understand the nature of the issue.
- Consider adding unsuccessful attempts to show thoroughness
- Tmux logs can be sufficient but can be horribly formatted
- Capture terminal outputs of significant steps separately

## Formatting and Redaction
Credentials & PII should be redacted from screenshots and anything else that is morally objectionable. Additionally consider:
- Adding annotations like arrows to images
- Adding image borders to make them stand out
- Cropping images to only display relevant information
- Including the URL or host address

### Screenshots
- Terminal output over screenshots of the terminal
- If anything has been cut or shortened, add the `<SNIP>`
- Don't paste with formatting - make it easy for them to copy & paste

### Terminal
- Redact credentials (inc password hashes usually leaving a few characters)
- Replace with `<REDACTED>` or `<PASSWORD REDACTED>`
- Consider colour code highlighting for important parts.

## What Not to Archive
- Any sensitive information - often just screenshotting the dir with the files in is enough
- We aren't there to do any harm and this is included in what we collect

## Emergency Vulnerability Notifications
If you discover a vulnerability that is directly exploitable, exposed to the internet and results in unauthenticated RCE, sensitive data exposure, or leverage weak/default credentials for the same. Its important to notify the client as they may want to issues an emergency fix.  Generally reporting any critical (or maybe high severity too) vulnerabilites is a good idea as the client may want to fix them before the assessment has finished.

## Components of a Report
### Writing an Attack Chain
This is the place where we walk through the steps taken to gain a foothold, move laterally, and compromise the domain. Add a summary and then the detailed steps.
- Summary
	- What were the results
	- The attack intent
	- The benefit of this walkthrough
- Detailed Walkthrough
	- What was done
	- What tools were used
	- What was the result
- Detailed Reproduction Steps
	- Show evidence (logs, screenshots etc)
	- Explain each step more

### Writing a Strong Executive Summary
One of the most important parts of the report. This report is potentially reviewed by a variety of stakeholders which can have direct consequences. Therefore it needs to have content for non-technical readers.

This summary is fighting for the technical people that fix & maintain this stuff. Its a chance for them to benefit in these areas (maybe secure more funding or resources).

**Key Assumptions (that may or may not be true)**
- It should be written for someone completely non-technical
- They aren't used to this language potentially and don't know concepts
- This may be their first time reading a penetration test report
- Their attention span is small
- Make sure they don't have to google things

**Do's**
- When talking about metrics, be as specific as possible
- It's a summary
- Describe the types of things you managed to access *(not "Domain Admin" but an account that could access HR docs, banking systems etc)*
- Describe the general things that need to improve to mitigate the risks discovered
- If possible (brave & experienced maybe) suggest a general expectation of how much effort would be necessary to fix some of this

**Do Not**
- Name or recommend specific vendors
- Use acronyms
- Waste time on non-impactful issues
- Use uncommon words and create distractions
- Reference a more technical section of the report

Categorise the nature of each of the findings and look for patterns (or lack of certain categories eg. missing patches) this can also be used to praise certain efforts that are effective

### Summary of Recommendations
Suggest short, medium, and long-term remediations which can be used to guide the client on what to fix and how long it might take. The client will often have input here and each recommendation should ideally tie back to a finding.

eg. Short term would be to patch the system, long-term would be to review their patch and vulnerability management processes to address any gaps that would prevent the issue from appearing again.

### Findings
Show off our work here, display the risks to their environment, help technical teams validate, diagnose & fix issues. 'Stock' findings can be written up but should always be tweaked to fit the client's context.

A finding should include at minimum:
- The description of the finding and what platform(s) the vulnerability affects
- Impact of the finding if left unresolved
- Affected systems, networks, environments, or applications
- Recommendations for how to address the problem
- Reference links with additional information about the finding and resolving it
- Steps to reproduce the issue and the evidence that you collected

Additional options include:
- CVE
- OWASP, MITRE IDs
- CVSS or similar score
- Ease of exploitation and probability of attack
- Any other information that might help learn about and mitigate the attack

#### Showing the Steps
- Break each step into its own figure, make it clear what happened
- If setup is required (eg. Metasploit modules), capture the full configuration so the reader can see what the exploit config should look like, and a second figure for running the exploit.
- Write a narrative between figures describing what is happening and what the tester is thinking.
- Add alternative toolkits if possible (just mention the tool and reference, don't exploit twice)

![[sample-finding-writeup.png]]

### Appendices
Some must appear, some are more dynamic. Make sure they don't unnecessarily bloat the report.

- **Scope** : show the assessment scope (URLs, Network ranges, etc)
- **Methodology** : Explain the repeatable process you followed to ensure assessment thoroughness and consistency
- **Severity Ratings** : If your severity doesn't map directly to a CVSS score or similar, this explains the criteria for your definitions. Needs to be defendable.
- **Biographies** : sometimes the client needs to prove that the tester was competent and qualified, it also gives piece of mind to the client.

- **Exploitation Attempts and Payloads** : what did you do and did you leave anything behind
- **Compromised credentials** : List accounts compromised
- **Configuration Changes** : what did you change and where
- **Additional Affected Scope** : If a list of hosts is too long then having in an appendix could help
- **Information Gathering** : Any *valuable* information you discovered that would be useful for them to know (this might be a supplementary spreadsheet)
- **Domain Password Analysis** : if you get a password database, it might be useful to reverse the hashed passwords, and use a tool like DPAT to get statistics to include about passwords.

## Report differences
- Some elements such as Attack Chain may not be included if compromise wasn't achieved
- External may focus on information gathering, OSINT, exposed services etc
- Some appendices may not be required.

## Tips / Tricks
- Tell a story with the report, why does something matter, what is the impact?
- Write as you go, don't leave the report to the end
- Stay organised
- Show as much evidence as possible without being overly verbose
- Clearly show what is being presented in screenshots (eg. [Greenshot](https://getgreenshot.org/) can add arrows/coloured boxes)
- Redact sensitive data wherever possible
- Redact tool outputs where possible to remove unprofessional terms (eg. `Pwn3d!` from CrackMapExec)
- Check grammar, spelling, and formatting (spell out acronyms the first time they are used)
- Make sure screenshots are clear
- Use raw command outputs where possible
- Keep it professional looking
- Establish a QA process
- Establish a style guide
- Use autosave
- Script and automate wherever possible