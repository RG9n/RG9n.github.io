# THM - Steel Mountain Write-Up

In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

The first step I always find useful is creating a directory for the room, and opening a terminal as root at the location (/home/kali/Desktop/CTF/TryHackMe/SteelMountain/).

## Task 1

1. Who is the employee of the month?

I am going to start this CTF by running a nmap scan on my assigned MACHINE_IP for this room. I will be looking for open ports that may have vulnerabilities so that I can take advantage of them using Metasploit.

'''
nmap 10.10.98.28 -p- -A -vv
'''

The scan I chose to run looks at all ports and runs an aggressive scan with very verbose information. It can sometimes be useful to output this in a grepable format by adding -oG <filename>.

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

After navigating to 10.10.98.28 to view the site, we see that we're in luck! Kind of... We see the employee but there is no name! Usually I would recommend doing some OSINT using a [reverse Image search](http://imgops.com/) here to try and find more info, but let's check the source first. 

Bingo! We got the answer for #1. It is common for information to be given away in the name of image files.

'''html
<img src="/img/BillHarper.png" style="width:200px;height:200px;"/>
'''

## Task 2
