## Manual OSINT
The [OSINT Framework website](https://osintframework.com/) provides links of many services that collect data about individuals from open-sources. Analysing this information and particularly what platform they have accounts on can give insight into their hobbies and/or background.

### Google Account IDs
Google stores a unique ID for each account that can be linked to any action by the user. To find this ID, you can search for an account in [google hangouts](https://mail.google.com/chat/u/0/) and then open the developer tools to find the ID. You can then query the google archives with this ID eg:
```
https://get.google.com/albumarchive/{google-id}
```

## Automated Toolings
### Maltego
[Maltego](https://www.maltego.com/) allows you to automate this search for information, the Community Edition has some limitations though.