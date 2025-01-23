Brute-forces potential pages on a site by searching for a common page name from a wordlist. This can allow you to find potentially hidden or unsecure pages.

```bash
(Kali@Kali) $ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 'html,php,txt' -t 100 -u 'URL'
```
With `gobuster` you need to specify a `URL (-u)` & `Wordlist (-w)` optional useful arguments are:
- `-x` file types to search for eg. `<URL>/<word_from_wordlist>.html`
- `-t` allows you to specify the number of threads to run the brute force on

Can also be done with the python based software `dirsearch`:
```bash
(Kali@Kali) $ dirsearch -u https://www.example.com
```