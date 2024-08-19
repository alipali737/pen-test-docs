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
- 