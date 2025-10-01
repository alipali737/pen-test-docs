![[Pasted image 20250106185830.png]]

```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
A vulnerability for example has a few key parts:
1. *Source* : where the information comes from / source of the vulnerability or trigger
2. *Process* : the information processing that occurs on our source data

## Source
The source is where the information / input comes from. This can be from a variety of sources, some include:
- *Code* : Some already executing/executed code can act as a source of information
- *Libraries* : documentation, data, templates, prebuilt code etc
- *Config* : Static or prescribed values to determine how the process should operate
- *APIs* : An interface for interacting with the program
- *User Input* : User entered data or interactions that could be a source of information

## Process
This is where the actual vulnerable logic lies (often in the source code of the program). Each of these elements could be targeted to exploit a vulnerability:
- *PID* : the Process-ID allows us to target the specific program executing
- *Input* : the input information that is going to be processed (from the source)
- *Data processing* : hard-coded logic that performs that processing on the input
- *Variables* : temporary stores of information during processing
- *Logging* : information is often logged to files, which could reveal key information after certain events occur

## Privileges
These present the control the process has over the system. They specify what a process can do and/or access, a significant factor in the severity of any vulnerabilities:
- *System* : the highest privileges that allow for system modifications (`SYSTEM` or `root`)
- *User* : privileges assigned to a specific user (could be a DB user with certain privileges to run the DB service)
- *Groups* : a collection of users that have permissions to perform a specific action
- *Policies* : govern application-specific commands (could apply to users or groups' use of these commands)
- *Rules* : actions handled within an application itself

## Destination
The destination is like the goal of the task, what is it that this task should do? For the task to have any use, it must generally return or store the data it has manipulated.
- *Local* : the system's environment in which the process occurred. The results and outcomes of the task are either processed further by a process or stored.
- *Network* : the results of the processing is forwarded to a remote interface (an IP, service or even another network)

## Log4J Example

| Step   | Log4J                                                                                                                             | Category      |
| ------ | --------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| **1.** | Attacker manipulates the User-Agent header with a JNDI lookup                                                                     | *Source*      |
| **2.** | The process misinterprets the data, leading to execution of the lookup                                                            | *Process*     |
| **3.** | The JNDI lookup is executed as administrator due to permission needed for logging (*needs access to protected dirs for security*) | *Privileges*  |
| **4.** | The JNDI lookup goes to the malicious server serving the malicious Java classa                                                    | *Destination* |
| ====   | ====                                                                                                                              | ====          |
| **5.** | The malicious java class is downloaded (deserialised) on the target                                                               | *Source*      |
| **6.** | The malicious java class is read by the process                                                                                   | *Process*     |
| **7.** | Malicious code is executed with administrator privileges                                                                          | *Privileges*  |
| **8.** | The code leads back to the attacker and they take control of the system                                                           | *Destination* |
