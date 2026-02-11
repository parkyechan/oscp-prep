# 0. Offsec Proving Grounds Walkthrough for OSCP prep

> The lab focuses on exploiting enumeration techniques such as SMB enumeration, Kerberoasting, and MSSQL enumeration. You'll also learn password cracking methods and ticket generation processes. This lab emphasizes practical skills in privilege escalation and credential harvesting.
# 1. Recon

## 1.1. Active Scanning
### 1.1.1. nmap

```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -p- --min-rate 1000 $IP -oG all_ports.gnmap
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-11 15:00 +04
Nmap scan report for 192.168.168.21
Host is up (0.082s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49668/tcp open  unknown
49676/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49693/tcp open  unknown
49708/tcp open  unknown
49799/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 209.52 seconds
```

`nmap` 결과 `nagoya-industries.com` 가 도메인임을 확인할 수 있다. 따라서 `/etc/hosts` 에 넣어준다. 

```bash
┌──(root㉿kali)-[/home/kali]
└─# ports=$(grep -oP '\d+(?=/open)' all_ports.gnmap | paste -sd "," -)

┌──(root㉿kali)-[/home/kali]
└─# nmap -sV -A -p$ports --min-rate 5000 $IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-11 15:04 +04
Nmap scan report for 192.168.168.21
Host is up (0.082s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
80/tcp    open  http              Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Nagoya Industries - Nagoya
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-02-11 11:04:42Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: nagoya-industries.com0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
|_ssl-date: 2026-02-11T11:06:21+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=nagoya.nagoya-industries.com
| Not valid before: 2026-02-10T10:58:32
|_Not valid after:  2026-08-12T10:58:32
| rdp-ntlm-info:
|   Target_Name: NAGOYA-IND
|   NetBIOS_Domain_Name: NAGOYA-IND
|   NetBIOS_Computer_Name: NAGOYA
|   DNS_Domain_Name: nagoya-industries.com
|   DNS_Computer_Name: nagoya.nagoya-industries.com
|   DNS_Tree_Name: nagoya-industries.com
|   Product_Version: 10.0.17763
|_  System_Time: 2026-02-11T11:05:42+00:00
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49666/tcp open  msrpc             Microsoft Windows RPC
49668/tcp open  msrpc             Microsoft Windows RPC
49676/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc             Microsoft Windows RPC
49679/tcp open  msrpc             Microsoft Windows RPC
49693/tcp open  msrpc             Microsoft Windows RPC
49708/tcp open  msrpc             Microsoft Windows RPC
49799/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: NAGOYA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-02-11T11:05:46
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   81.64 ms 192.168.45.1
2   81.63 ms 192.168.45.254
3   81.70 ms 192.168.251.1
4   81.78 ms 192.168.168.21

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.91 seconds
```
### 1.1.2. ffuf

```bash
┌──(root㉿kali)-[/home/kali]
└─# ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 200 -e .php -fc 403

        /'___\  /'___\           / ___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.168.21/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

Index                   [Status: 200, Size: 3530, Words: 831, Lines: 79, Duration: 83ms]
error                   [Status: 200, Size: 3128, Words: 652, Lines: 69, Duration: 87ms]
favicon.ico             [Status: 200, Size: 5430, Words: 9, Lines: 1, Duration: 81ms]
index                   [Status: 200, Size: 3530, Words: 831, Lines: 79, Duration: 83ms]
team                    [Status: 200, Size: 6896, Words: 3634, Lines: 180, Duration: 94ms]
:: Progress: [9492/9492] :: Job [1/1] :: 2469 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

## 1.2. SMB Scanning
### 1.2.1. smbmap

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# smbmap -H $IP

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[!] Access denied on 192.168.168.21, no fun for you...
[*] Closed 1 connections

┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# smbclient -N -L //$IP
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.168.21 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
### 1.2.2. smbclient

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# smbclient -N -L //$IP
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.168.21 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

## 1.3. Web Discovery

### 1.3.1. Port 80



![](../images/WindowsAD-02.%20Nagoya.png)



![](../images/WindowsAD-02.%20Nagoya-1.png)



```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# ../../tools/username-anarchy/username-anarchy -i users > users.txt

┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# cat users.txt
matthew
matthewharrison
matthew.harrison
matthewh
mattharr
m.harrison
mharrison
hmatthew
[...SNIP...]
```

## 1.4. Kerberos

### 1.4.1. GetNpUsers

`impacket-GetNPUsers` 를 통해 돌려봤으나, 특별한 내용은 나오지 않았다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# impacket-GetNPUsers 'nagoya-industries.com/' -usersfile users.txt -format hashcat -outputfile hash -dc-ip $IP
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User matthew.harrison doesnt have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User emma.miah doesnt have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[...SNIP...]
```

### 1.4.2. Kerbrute

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# kerbrute userenum -d nagoya-industries.com --dc $IP users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 02/11/26 - Ronnie Flathers @ropnop

2026/02/11 15:49:49 >  Using KDC(s):
2026/02/11 15:49:49 >  	192.168.168.21:88

2026/02/11 15:49:49 >  [+] VALID USERNAME:	 matthew.harrison@nagoya-industries.com
2026/02/11 15:49:49 >  [+] VALID USERNAME:	 emma.miah@nagoya-industries.com
2026/02/11 15:49:49 >  [+] VALID USERNAME:	 rebecca.bell@nagoya-industries.com
2026/02/11 15:49:49 >  [+] VALID USERNAME:	 scott.gardner@nagoya-industries.com
2026/02/11 15:49:49 >  [+] VALID USERNAME:	 terry.edwards@nagoya-industries.com
2026/02/11 15:49:49 >  [+] VALID USERNAME:	 holly.matthews@nagoya-industries.com
2026/02/11 15:49:49 >  [+] VALID USERNAME:	 anne.jenkins@nagoya-industries.com
2026/02/11 15:49:50 >  [+] VALID USERNAME:	 brett.naylor@nagoya-industries.com
2026/02/11 15:49:50 >  [+] VALID USERNAME:	 melissa.mitchell@nagoya-industries.com
2026/02/11 15:49:50 >  [+] VALID USERNAME:	 craig.carr@nagoya-industries.com
2026/02/11 15:49:50 >  [+] VALID USERNAME:	 fiona.clark@nagoya-industries.com
2026/02/11 15:49:50 >  [+] VALID USERNAME:	 patrick.martin@nagoya-industries.com
2026/02/11 15:49:50 >  [+] VALID USERNAME:	 kate.watson@nagoya-industries.com
2026/02/11 15:49:50 >  [+] VALID USERNAME:	 kirsty.norris@nagoya-industries.com
2026/02/11 15:49:50 >  [+] VALID USERNAME:	 andrea.hayes@nagoya-industries.com
2026/02/11 15:49:50 >  [+] VALID USERNAME:	 abigail.hughes@nagoya-industries.com
2026/02/11 15:49:51 >  [+] VALID USERNAME:	 melanie.watson@nagoya-industries.com
2026/02/11 15:49:51 >  [+] VALID USERNAME:	 frances.ward@nagoya-industries.com
2026/02/11 15:49:51 >  [+] VALID USERNAME:	 sylvia.king@nagoya-industries.com
2026/02/11 15:49:51 >  [+] VALID USERNAME:	 wayne.hartley@nagoya-industries.com
2026/02/11 15:49:51 >  [+] VALID USERNAME:	 iain.white@nagoya-industries.com
2026/02/11 15:49:51 >  [+] VALID USERNAME:	 joanna.wood@nagoya-industries.com
2026/02/11 15:49:51 >  [+] VALID USERNAME:	 bethan.webster@nagoya-industries.com
2026/02/11 15:49:51 >  [+] VALID USERNAME:	 elaine.brady@nagoya-industries.com
2026/02/11 15:49:52 >  [+] VALID USERNAME:	 christopher.lewis@nagoya-industries.com
2026/02/11 15:49:52 >  [+] VALID USERNAME:	 megan.johnson@nagoya-industries.com
2026/02/11 15:49:52 >  [+] VALID USERNAME:	 damien.chapman@nagoya-industries.com
2026/02/11 15:49:52 >  [+] VALID USERNAME:	 joanne.lewis@nagoya-industries.com
2026/02/11 15:49:52 >  Done! Tested 405 usernames (28 valid) in 3.418 seconds
```










