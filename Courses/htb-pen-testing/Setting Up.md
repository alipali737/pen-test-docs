Its useful to have an image that can be deployed whenever, each test should be on a fresh, clean install of the attack box.

[ParrotOS](https://www.parrotsec.org/download/) has a really comfortable security edition that can be run as a VM. Having a setup folder structure inside the VM will speed up the setup process.

We should template as much as possible to speed up our efficiency. We should also keep a findings database, report templates, checklists, cheatsheets etc.

[OpenVPN](https://openvpn.net/) allows us to connect to platforms via a VPN, encrypting our traffic at least.
We can see the networks accessible via the VPN with `netstat -rn`