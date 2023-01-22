---
layout: page
title: Virtualization
parent: Setting Up
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

`Virtualization` is an abstraction of physical computing resources. Both hardware and software components can be abstracted. Virtualization involves the abstraction of physical computing resources such as hardware, software, storage, and network components

In virtualization, we distinguish between:
-   Hardware virtualization
-   Application virtualization
-   Storage virtualization
-   Data virtualization
-   Network virtualization

### Hardware Virtualization
enable hardware components to be made available independently of their physical basis using [hypervisor](https://en.wikipedia.org/wiki/Hypervisor) software. Best known example is the `virtual machine (VM)`. 

![Hardware Virtualization Stack]({{ site.baseurl }}/assets/images/setting-up/hardware-virtualization-stack.png)

**Primary Benefits:**
1. Applications and services of a VM do not interfere with each other
2. Complete independence of the guest system from the host system's operating system and the underlying physical hardware
3. VMs can be moved or cloned to other systems by simple copying
4. Hardware resources can be dynamically allocated via the hypervisor
5. Better and more efficient utilization of existing hardware resources
6. Shorter provisioning times for systems and applications
7. Simplified management of virtual systems
8. Higher availability of VMs due to independence from physical resources

### Introduction to VirtualBox
An excellent and free alternative to VMware Workstation is [VirtualBox](https://www.virtualbox.org/). 

With VirtualBox, hard disks are emulated in container files, called Virtual Disk Images (`VDI`). Aside from VDI format, VirtualBox can also handle hard disk files from VMware virtualization products (`.vmdk`), the `Virtual Hard Disk` format (`.vhd`), and others. We can also convert these external formats using the VBoxManager command-line tool that is part of VirtualBox. We can install VirtualBox from the command line or download the installation file from the [official website](https://www.virtualbox.org/wiki/Downloads) and install it manually.

Also, we have the possibility and function to `encrypt` the VM, which we should always use.

### Networking multiple VM's together
Using VirtualBox multiple VM's can be added to the same network without losing access to the internet. This can be done via the following steps to create a custom **NAT Network**:

1. To go `Tools > Preferences > Network`
1. Create a new Network and give it a name & IP
1. In the network settings for each VM select `NAT Network` as the adapter
1. Select the custom network name
1. Test the connections between the boxes using Ping or NMap