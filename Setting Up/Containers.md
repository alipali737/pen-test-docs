---
layout: page
title: Containers
---
# Containers
An isolated group of processes running on a single host that corresponds to a complete application, including its configuration and dependencies.

A container isn't a VM as it **doesn't** contain its `operating system` or `kernel`. Therefore are not a virtualized operating system. They are also referred to as application virtualization in this context.

| Virtual Machine | Container |
| --- | --- |
| Contain applications and the complete OS | Contain applications and only the necessary OS components such as libs and bins |
| A hypervisor provides virtualization | The OS within the container engine provides its own virtualization |
| Multiple VMs run in isolation from each other on a physical server | Several containers run isolated from each other on one operating system |

### Docker
[Docker](https://www.docker.com/get-started) is an open-source software that can isolate applications in containers. Docker stores programs together with their dependencies in `images`.

### Vagrant
[Vagrant](https://www.vagrantup.com/) is a tool that can create, configure and manage virtual machines or vm environments. The VMs are created and configured using a `Vagrantfile`. 

![windows swarm demo](/assets/setting-up/windows-swarm-demo.png)