# Logging CLI Tools

Logging is essential for both documentation and our protection. If third parties attack the company during our penetration test and damage occurs, we can prove that the damage did not result from our activities. For this, we can use the tools `script` and `date`. 

`Date` can be used to display the exact date and time of each command in our command line. 

With the help of `script`, every command and the subsequent result is saved in a background file. To display the date and time, we can replace the `PS1` variable in our `.bashrc` file with the following content.

```bash
PS1="\[\033[1;32m\]\342\224\200\$([[ \$(/opt/vpnbash.sh) == *\"10.\"* ]] && echo \"[\[\033[1;34m\]\$(/opt/vpnserver.sh)\[\033[1;32m\]]\342\224\200[\[\033[1;37m\]\$(/opt/vpnbash.sh)\[\033[1;32m\]]\342\224\200\")[\[\033[1;37m\]\u\[\033[01;32m\]@\[\033[01;34m\]\h\[\033[1;32m\]]\342\224\200[\[\033[1;37m\]\w\[\033[1;32m\]]\n\[\033[1;32m\]\342\224\224\342\224\200\342\224\200\342\225\274 [\[\e[01;33m\]$(date +%D-%r)\[\e[01;32m\]]\\$ \[\e[0m\]"
```

ZSH version

```shell
{% raw %}
PROMPT='%B┌──(%F{blue}%n@%m%F{reset})─[%F{#FFFFFF}%~%F{reset}]
%B└─%F{red}$%F{#FFFFFF} '
RPROMPT='[%D{\%d/%m/%Y} %*]'
{% endraw %}
```

This can also be achieved similarly with `Oh-My-ZSH` by adding the following in the `.zshrc` file.

```shell
{% raw %}
autoload -Uz vcs_info

precmd() {
        # Sets the tab title to current dir
        echo -ne "\e]1;${PWD##*/}\a"

        vcs_info
}

zstyle ':vcs_info:git:*' formats '%b'
setopt PROMPT_SUBST

# Configure PROMPT & RPROMPT
PROMPT='%B┌──[%F{#FFFFFF}%*%F{reset}]─[%F{#FFFFFF}%~%F{reset}]
%B└─[%F{magenta}${vcs_info_msg_0_}%F{reset}]─%F{red}$%F{#FFFFFF} '

TMOUT=1
TRAPALRM() {
        zle reset-prompt
}
{% endraw %}
```

On **Linux** *'script'* can be used:
````shell
$ script 03-21-2021-0200pm-exploitation.log

$ exit
````

On **Windows** *'Start-Transcript'* can be used to log everything run
```powershell
C:\> Start-Transcript -Path "C:\Pentesting\03-21-2021-0200pm-exploitation.log"

Transcript started, output file is C:\Pentesting\03-21-2021-0200pm-exploitation.log

C:\> Stop-Transcript
```

Recommended to define the name of the log in advance eg. `<date>-<start time>-<name>.log`
