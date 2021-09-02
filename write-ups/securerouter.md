# Project: Securing your Home Router

Reason: So0o0o many [households/targets](https://www.security.org/antivirus/antivirus-consumer-report-annual/) to hit, poor/free A/V, legacy software, free botnet zombies essentially. Even higher risk currently with all of the remote work.

We'll start with securing direct access to your internal network from the internet through your router either via the internet or local access attempts. Unfortunately, that's just the beginning of securing a home network... I might do multiple chapters on this depending how it goes.

# Important note: Following this perfectly to the fullest extent of protection will not secure your network and garuntee against compromise. These are only ways to increase security. If you don't want a home network to be hacked for sure, don't have one ;)

## Brief Summary of holes in a Home Network

There are four main entry points:

1. Straight from internet to router through public IP holes (covered here)
1. From physical home connection attempts ([Wardriving](https://www.pandasecurity.com/en/mediacenter/security/wardriving/), etc. covered here)
1. From internal threat (compromised friends joining network, phishing, etc) - partially covered might go more in-depth on this in a future project.
1. [IoT](https://wiki.owasp.org/index.php/OWASP_Internet_of_Things_Project) (lightbulbs, security cameras, alexa, etc.) - not covered but might be in the future in depth, lots of legacy software and potential exploits.

I recommend taking a look at the IoT resource, it's a really neat OWASP wiki. It is a little dated though.

## Router Necessities

I'll start by listing everything we'll be covering here in terms of hardening and how it will prevent attacks. Also the risk to convenience involved... because a lot of security can be time consuming and you will have to decide if the trade-off is worth it.

1. Ensure router username AND password are changed
1. Adjust login attempts
1. Firewall enabled
1. Review forwarded ports
1. Enable guest wifi
1. Alter SSID for Guest and Main network (ideally your guest wifi will appear as your main wifi)
1. Ensure remote management is disabled
1. Disable [WAN](https://www.comptia.org/content/guides/what-is-a-wide-area-network)
1. [WPA/WPA2/WPA3](https://ipcisco.com/lesson/wireless-security-protocols/)
1. Disable [WPS](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Setup)
1. [UPnP](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=upnp)
1. MAC Authentication

## Begin Hardening your Network!

### Ensure Router Username and Password are Changed

Open cmd, type in ipconfig /all - scroll to Wireless LAN or whatever interface and plug your default gateway into your browser of choice.

```
Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : dnstorouter.com
   Description . . . . . . . . . . . : N/A
   Physical Address. . . . . . . . . : Current device's MAC address you will need later if doing MAC Auth.
   DHCP Enabled. . . . . . . . . . . : N/A
   Autoconfiguration Enabled . . . . : N/A
   Link-local IPv6 Address . . . . . : private ipv6 for the device you're on currently in the network.
   IPv4 Address. . . . . . . . . . . : private ipv4 for the device you're on currently in the network.
   Subnet Mask . . . . . . . . . . . : N/A
   Lease Obtained. . . . . . . . . . : N/A
   Lease Expires . . . . . . . . . . : N/A
   Default Gateway . . . . . . . . . : 192.168.1.1 - gateway to your network administration.
```

Sign into your router using the credentials that are default or hopefully instead, located on your router sticker. If not on either of these, contact ur Internet Service Provider (ISP).

You might get some insecure connection because it's http, that's fine we're not worried about that right now accept and sign into the admin.

Each router is different for these steps, so you'll need some IT experience or router documentation to go through this.

### Adjust Login Attempts

In the login configuration, set your maximum unsuccessful attempts to a number you want. I went with 3 to keep from getting trolled by capslock. This will help prevent against bruteforce attempts.

### Enable the Firewall

I'm hoping this is at least at medium security (accepts outbound but not inbound connections). If not, ensure it is. I'd personally recommend rejecting both inbound and outbound connections until you're done with the security changes for both IPv4 and IPv6.

### Review Forwarded Ports

On a home network - you shouldn't have any of these. Every single one is a hole to the scary outside interwebs. We'll scan the network later to see what's open, but this is a quick way to check.

### Enable Guest WiFi

Navigate to WiFi - then the Guest Network section. If your router doesn't have this - it should.

This is a network you can put friends on that is a little slower but if they join with a compromised device, lowers the chance of lateral movement to your clean machines by putting them on a separate network subnet.

Enable and set a secure password.

### Alter SSID for Guest and Main network.

The Service Set Identifier (SSID) is your network's name. Don't let people know it's the guest WiFi by renaming the SSID and removing "-guest".

You can leave discovery open for the guest, but I'd remove it for the main network and disassociate the names. 

Best security = disable discovery for both.

Example:

```
Main network name: Alph4Netw0rk! (Name can be used like a second password since they do not have the name)
Discoverable: No

Guest network name: !asSecurenet (removed "-guest" and disassociated the namng convention from the main network) 
Discoverable: Yes/No
```

It is important to change the SSID because the default name gives away a lot of information about the router. This information can then be used alongside a [vulnerability database](https://www.exploit-db.com/search?q=router).

###  Ensure Remote Management is Disabled

Remote management allows anyone from the internet to reach your router's WAN admin login. This is something that should NEVER be enabled. 

### Disable WAN

Remove WAN ICMP and UDP echo/traceroute queries and requests. 

This may interfere with any diagnostics tools you try to run from the outside of your network, but also helps to protect from scans by adversaries to see if you exist.

### WPA/WPA2/WPA3

### Disable WPS

Go into the WiFi section and find the WiFi Protected Setup. Disable this option, it is only used to get access to the network physically by clicking a button on the router.

### UPnP

Some routers have UPnP enabled. Disable this in the UPnP settings. If you want to use it, make sure you keep it updated and set it to automatically clean old unused UPnP Services.

### MAC Authentication

This will allow you in the advanced settings to create a whitelist/blacklist for the Physical Address (see first section of hardening ipconfig /all for how to find MAC). This can be bypassed by MAC spoofing (I'll let you research this on your own - as it's out of scope for this write-up), but will still help to harden the network.

### I would do a quick router reboot and check to make sure the settings don't reset or change after reboot.

Once you've verified the settings are good, let's move on.

## Test your defenses!

### Scan your network

Let's start at your den. 

* Go to google and type in what is my IP? (make sure you don't have a VPN)

* Write it down on a peice of paper.

* Walk to a friends/family's den. (make sure they know what you're going to be doing)

* Setup your laptop you will be using.

Your laptop will need [nmap](https://nmap.org/) for this activity.

Now that we're ready to start, let's start by checking if your router will respond back to ping requests.

```ps
PS C:\Users\RG9n> ping YOURDENIPYOUWROTEDOWN

Pinging YOURDENIPYOUWROTEDOWN with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.
Request timed out.

Ping statistics for YOURDENIPYOUWROTEDOWN:
    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),
```

Nice, we were successful in making our network somewhat dark.

If this is not your result and the pings are returning, go back to the **Disable WAN** section.

Now try to nmap your IP with a simple check.

```
PS C:\Users\RG9n> nmap YOURDENIPYOUWROTEDOWN -vv
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-02 09:12 TimeZone
Initiating Ping Scan at 09:12
Scanning YOURDENIPYOUWROTEDOWN [4 ports]
Completed Ping Scan at 09:12, 3.11s elapsed (1 total hosts)
Nmap scan report for YOURDENIPYOUWROTEDOWN [host down, received no-response]
Read data files from: C:\Program Files (x86)\Nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.37 seconds
           Raw packets sent: 8 (304B) | Rcvd: 0 (0B)
```

Great, so we stop the ping probes and might get missed by a scan. However, they can still scan if they use -Pn to assume the host is online. So let's go ahead and run a full scan with that -Pn now.

You might want to grab a beer or something, it will take awhile.

```
PS C:\Users\rg9in> nmap YOURDENIPYOUWROTEDOWN -A -p- -vv -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-02 09:20 TimeZone
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:20
Completed NSE at 09:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:20
Completed NSE at 09:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:20
Completed NSE at 09:20, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 09:20
Completed Parallel DNS resolution of 1 host. at 09:21, 11.28s elapsed
Initiating SYN Stealth Scan at 09:21
Scanning SCANNING-YOUR-DEN-IP-HERE.redacted.isp.provider.den (YOURDENIPYOUWROTEDOWN) [65535 ports]
SYN Stealth Scan Timing: About 0.30% done
SYN Stealth Scan Timing: About 0.53% done
SYN Stealth Scan Timing: About 0.76% done
SYN Stealth Scan Timing: About 0.98% done
SYN Stealth Scan Timing: About 1.21% done; ETC: 13:00 (3:37:09 remaining)
SYN Stealth Scan Timing: About 6.45% done; ETC: 13:01 (3:26:06 remaining)
SYN Stealth Scan Timing: About 11.51% done; ETC: 13:01 (3:15:03 remaining)
SYN Stealth Scan Timing: About 16.51% done; ETC: 13:01 (3:03:59 remaining)
SYN Stealth Scan Timing: About 21.56% done; ETC: 13:01 (2:52:56 remaining)
SYN Stealth Scan Timing: About 26.54% done; ETC: 13:01 (2:41:54 remaining)
SYN Stealth Scan Timing: About 31.55% done; ETC: 13:01 (2:30:52 remaining)
SYN Stealth Scan Timing: About 36.59% done; ETC: 13:01 (2:19:49 remaining)
SYN Stealth Scan Timing: About 41.59% done; ETC: 13:01 (2:08:46 remaining)
SYN Stealth Scan Timing: About 46.61% done; ETC: 13:01 (1:57:43 remaining)
SYN Stealth Scan Timing: About 51.61% done; ETC: 13:01 (1:46:41 remaining)
SYN Stealth Scan Timing: About 56.63% done; ETC: 13:01 (1:35:37 remaining)
SYN Stealth Scan Timing: About 61.65% done; ETC: 13:01 (1:24:33 remaining)
SYN Stealth Scan Timing: About 66.66% done; ETC: 13:01 (1:13:30 remaining)
SYN Stealth Scan Timing: About 71.67% done; ETC: 13:01 (1:02:28 remaining)
SYN Stealth Scan Timing: About 76.69% done; ETC: 13:01 (0:51:24 remaining)
SYN Stealth Scan Timing: About 81.69% done; ETC: 13:01 (0:40:22 remaining)
SYN Stealth Scan Timing: About 86.69% done; ETC: 13:01 (0:29:20 remaining)
SYN Stealth Scan Timing: About 91.70% done; ETC: 13:01 (0:18:18 remaining)
SYN Stealth Scan Timing: About 96.70% done; ETC: 13:01 (0:07:16 remaining)
Completed SYN Stealth Scan at 13:01, 13231.93s elapsed (65535 total ports)
Initiating Service scan at 13:01
Initiating OS detection (try #1) against SCANNING-YOUR-DEN-IP-HERE.redacted.isp.provider.den (YOURDENIPYOUWROTEDOWN)
Retrying OS detection (try #2) against SCANNING-YOUR-DEN-IP-HERE.redacted.isp.provider.den (YOURDENIPYOUWROTEDOWN)
Initiating Traceroute at 13:01
Completed Traceroute at 13:01, 9.12s elapsed
NSE: Script scanning 68.134.16.153.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
Nmap scan report for SCANNING-YOUR-DEN-IP-HERE.redacted.isp.provider.den (YOURDENIPYOUWROTEDOWN)
Host is up, received user-set.
All 65535 scanned ports on SCANNING-YOUR-DEN-IP-HERE.redacted.isp.provider.den (YOURDENIPYOUWROTEDOWN) are filtered because of 65535 no-responses
Too many fingerprints match this host to give specific OS details
TCP/IP fingerprint:
REDACTED
U1(R=N)
IE(R=N)


TRACEROUTE (using proto 1/icmp)
HOP RTT    ADDRESS
1   ... 30

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
Read data files from: C:\Program Files (x86)\Nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13263.05 seconds
           Raw packets sent: 131208 (5.776MB) | Rcvd: 10 (2.420KB)
```

* -A is an aggressive scan that enables OS detection, version detection, script scanning, and traceroute.
* -p- scans through all 65535 ports.
* -vv enables very verbose response.
* -Pn disables ping probing and host discovery.
* -oN/oX/oG/oA filename you can use this to output the results.

Once your nmap is done, ensure no ports are open. If they are, go back to review forwarded ports and UPnP 

# Congrats! Your router entry is more secure now. However, there are several other ways into a network like Phishing, IoT, etc so always be on the lookout for strange activity.
