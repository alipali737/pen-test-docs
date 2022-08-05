---
layout: page
title: Operating Systems
parent: Setting Up
---

# Operating Systems

## Linux
Most widely used OS for pen testing. Best to develop a certain standard for it that always leads to the same setup we are used to.

### Penetration Testing Distributions
Personal preference depending on needs and desires.
Some of the most popluar lnclude:
- [ParrotOS](https://www.parrotsec.org/) (`Pwnbox`)
- [Kali Linux](https://kali.org/) (`Personal Preference`)
- [BlackArch](https://blackarch.org/)
- [BackBox](https://linux.backbox.org/)

### Setting Up Kali on VirtualBox
[Official Documentation](https://www.kali.org/docs/virtualization/install-virtualbox-guest-vm/)
**Installing:**
1. Download the kali linux files
2. Import the ova file into virtual box
3. Follow the setup guide above to setup the system resources
4. Setup disk encryption with a secure password in pass manager

**System Setup**
1. Default login username: `kali` & password `kali`
2. Change default password of root user running `passwd` in terminal
3. Change the default SSH keys
```shell
$ cd /etc/ssh/
$ dpkg-reconfigure openssh-server
```
4. Update the system with:
```shell
$ sudo apt update -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y
```

**Installing Additional Tools**
It's important to have an up-to-date tools list to add too [personal tools list](https://alipali737.github.io/pen-test-docs/setting-up/personal-tools-list.html)
- To install specific tools use:
```shell
$ sudo apt install netcat ncat nmap ... -y
```
- To install from a list:
```shell
$ sudo apt install $(cat tools.list | tr "\n" " ") -y
```
- Clone any useful repos from git from [useful git repos](https://alipali737.github.io/pen-test-docs/setting-up/useful-git-repos.html)

**Snapshotting**
- After we setup our OS its important to snapshot it so we can return to this state if we ever need too. 
- It's good practice to take snapshots of our system through a pen test in case something goes wrong (like taking a backup)
- It is also useful when you are about to change major configuration options.

**Taking a snapshot**
1. Ensure the machine is turned off
2. Go into the snapshots section of VB
3. Take a new snapshot giving it a name and description

## Windows
Having a windows system can be a great penetration testing platform.

**Benefits:**
- Blends into most enterprise environments
- Easier to navigate and communicate with other hosts on an Active Directory domain if we use Windows versus Linux and some Python tooling
- Traversing SMB *(Server Message Block protocol, a network file sharing protocol)* and utilizing shares is much easier

**Building our penetration testing platform can help us in multiple ways:**
1. Since we built it and only have tool necessary, we have a better understanding of everything happening.
2. We can ensure we do not having any unnecessary services running tha tcould potentially be a risk to ourselves and the customer.
3. Flexability of having multiple OS types.
4. Can also act as a testbed for payloads and exploits before launching them.
5. Building + testing ourselves means we know they will function as intended during an engagement.

`Windows Subsystem for Linux (WSL)` allows for Linux OS's to run alongside our windows install. This gives us space to run tools developed for Linux right inside our Windows host.

Since the purpose of this platform is to perform penetration test functions, it will require some changes made to the host's security settings. We need to ensure we isolate these tools off as `Windows Defender` will delete any detected files and applications, breaking our setup.

### Installing the Windows VM
Windows 10 VMs can be found build as ISO files [here](https://www.microsoft.com/en-gb/software-download/windows10) but you need to take a screenshot of the VM once it has been configured.

Windows 10 can get pretty intensive so it's recommended to give it `2 CPU cores` & `4Gb+ RAM` & `80Gb+ Storage`

When installing a windows VM you need to make sure you disable network so you don't need to login with a microsoft account.

You can also install windows 10 at different [patches](https://support.microsoft.com/en-us/topic/windows-10-update-history-24ea91f4-36e7-d8fd-0ddb-d79d9d0cdbda) and [versions](https://docs.microsoft.com/en-us/windows/release-health/release-information) which means you can mimic your target system to test exploits out before deployment. We can have a different snapshot for each version and update our system step by step. Updates and patches can be downloaded from [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=KB4550994)