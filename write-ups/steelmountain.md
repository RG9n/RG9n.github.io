# THM - Steel Mountain Write-Up

In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

The first step I always find useful is creating a directory for the room, and opening a terminal as root at the location (/home/kali/Desktop/CTF/TryHackMe/SteelMountain/).

1. Who is the employee of the month?

I am going to start this CTF by running a nmap scan on my assigned MACHINE_IP for this room. I will be looking for open ports that may have vulnerabilities so that I can take advantage of them using Metasploit.
'''linux
nmap 10.10.98.28 -p- -A -vv
'''
The scan I chose to run looks at all ports and runs an aggressive scan with very verbose information. It can sometimes be useful to output this in a grepable format by adding -oG <filename>.

Here is what I managed to find with my scan that I believe will be useful:

2. 
