---
layout: page
title: Application Security Testing Methods
parent: Testing
grand_parent: Knowledge
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
A combination of this methods is necessary for effective testing of an application, no one method can cover everything or every possible context. A mix of DAST & IAST is often very common.

## Static Application Security Testing (SAST)

## Dynamic Application Security Testing (DAST)

## Interactive Application Security Testing (IAST)
IAST focuses on how an activity "interacts" with the application functionality while it runs. The core of an IAST tool is sensor modules. These modules keep track of application behaviour while the tests are running. These sensors often have access to:
- Entire code base
- Dataflow and control flow
- System configuration data
- Web components
- Back-end connection data

Unlike SAST & DAST methods, which view the application in isolation (without context of other external security measures), IAST looks as all the components and systems the application interacts with at runtime.

A typical IAST works as:
1. **Instrumentation**: The IAST deploys sensors & agents alongside the application. These insert into the application's code or runtime environment. They monitor and trace the flow of data and method calls between components.
2. **Runtime Analysis**: As the application runs, the IAST collects data on how the components interact, including data flow and control flow. This helps identify security issues that arise due to the integration of various components.
3. **Vulnerability Detection**: The IAST agents analyse the collected data to detect security vulnerabilities. By understanding the runtime behaviour, IAST can provide accurate vulnerability identification and reduce false positives.
4. **Real-time Feedback**: As IAST's operate at runtime, they can provide real-time feedback. This enables quick identification of security issues.

This can be particularly effective for identifying vulnerabilities when combined with OAST methods.

## Out-of-Band Application Security Testing (OAST)
OAST, like DAST is testing a running application with carefully crafted payloads. Although, this method is primarily for automated scanning, it can be performed manually if required.

The main benefit of this method is to detect invisible (blind) vulnerabilities with a high accuracy. The process consists of sending attack payloads to a target which cause an interaction with an external system that is in the tester's control, that sits outside the target domain. Because the tester has insight into the external server, the requests the target application makes can be examined and can be used to detect blind vulnerabilities (as well as standard ones too).

### Advantages
- As it is a form of DAST, this process rarely produces false positives meaning the reports can be trusted.
- It can find a greater number of vulnerabilities than of DAST as it has a wider number of tests it can conduct.
- Like DAST, it doesn't require specific language implementations (unlike SAST) so you only require one scanner for many applications.

### Disadvantages
- No scanner or testing method can ever be perfect, some vulnerabilities will be missed.
- 