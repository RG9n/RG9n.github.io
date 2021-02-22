# TryHackMe - [MAL: Researching](https://tryhackme.com/room/malresearching) Write-Up

## Task 1: Intro

"You can expect to learn about file checksums, why these values are important in not only day-to-day life but more so how we can utilise them in malware analysis. The first few tasks are theory-heavy, so bear with me. However, towards the end of the room, you will be generating your own checksums, learning how to use online sandboxing, and analysing the reports generated from these."

## Task 2: Deploy!

Deploy your machine, it will not be used yet but it can take awhile to boot.

## Task 3: Checksums 101

### This is really just a reading section. Read and answer the questions.

**1) Name the term for an individual piece of binary**
**2) What are checksums also known as?**
**3) Name the algorithm that is next in the series after SHA-256**
**4) According to this task, how long will you need to hash 6 million files before a MD5 hash collision occurs?**

This should actually be [billion](https://stackoverflow.com/questions/201705/how-many-random-elements-before-md5-produces-collisions), the question is incorrect. 

**5) Who developed the MD5 algorithm?**

Information on [MD5](https://www.sciencedirect.com/topics/computer-science/message-digest-algorithm-5#:~:text=MD5%20is%20the%20Message%20Digest,based%20on%20any%20input%20length.).

[Shattered.io](https://shattered.io/static/shattered.pdf) contains a good article on hash collision.

## Task 4: Online Sandboxing

This section is very important! You **DO NOT** want this stuff getting to your host system. 

There have been [VM vulnerabilities](https://nvd.nist.gov/vuln/detail/CVE-2018-2689) that malware can escape.

They also have been found to detect VMs/sandboxes.

Here's a good SANS article on [Detecting Malware and Sandbox Evasion Techniques](https://www.sans.org/reading-room/whitepapers/forensics/detecting-malware-sandbox-evasion-techniques-36667)

Some useful sandboxes
* [any.run](https://any.run/)
* [hybrid-analysis](https://hybrid-analysis.com/)

You are then given an any.run [report](https://any.run/report/c378387344e0a552dc065de6bfa607fd26e0b5c569751c79fbf9c6f2e91c9807/3363fde4-111b-4aaa-b73d-e4144433c284) for an emotet doc to investigate and answer the questions.

**1) Name the key term for the type of malware that Emotet is classified as**

Threats part of General Info.

**2) Research time! What type of emails does Emotet use as its payload?**

[Alert](https://us-cert.cisa.gov/ncas/alerts/aa20-280a#:~:text=Technical%20Details,Phishing%3A%20Spearphishing%20Link%20%5BT1566.) on emotet.

**3) Begin analysing the report, what is the timestamp of when the analysis was made?**

Located in General Info below the Threats section.

**4) Name the file that is detected as a "Network Trojan"**

Located in Behavior Activities.

**5) What is the PID of the first HTTP GET request?**

Located in Network activity for HTTP requests. (Done with powershell)

**6) What is the only DNS request that is made after the sample is executed?**

Check the DNS requests.

Interesting new read I found on disruption of emotet from [justice.gov](https://www.justice.gov/opa/pr/emotet-botnet-disrupted-international-cyber-operation).

## Task 5: Practical: Calculating & Reporting Checksums

Now it's time to RDP into that box we deployed with the credentials given (cmnatic;Tryhackm3!)

The device should contain all of the tools required on the Desktop.

**1) Using the HashTab tool, what is the MD5 checksum for "LoginForm.exe"?**

* First, let's go in and check the properties (right click) of the LoginForm binary.

* Next, navigate to the file hashes tab. This tab is here because we have hashtab already on the device.

**2) Using Get-FileHash in Powershell, retrieve the SHA256 of "TryHackMe.exe"**

Now we're going to move onto using the Get-FileHash cmdlet in powershell.

* Open powershell and navigate to the Desktop.
* Use the cmdlet to get the filehash of the TryHackMe binary.

```ps
PS C:\Users\cmnatic> cd Desktop
PS C:\Users\cmnatic\Desktop> Get-FileHash TryHackMe.exe -Algorithm SHA256

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          6F870C80361062E8631282D31A16872835F7962222457730BC55676A61AD1EE0       C:\Users\cmnatic\Desktop\TryH...
```

**3) What would be the syntax to retrieve the SHA256 checksum of "TryHackMe.exe" using CertUtil in Powershell?**

Now we're going to use certutil (for if we do not have FileHash installed)

```ps
CertUtil -hashfile TryHackMe.exe SHA256
```

## Task 6: VirusTotal

This section gives you a VirusTotal [report](https://www.virustotal.com/gui/file/6f870c80361062e8631282d31a16872835f7962222457730bc55676a61ad1ee0/details) to look at.

It appears to be HxD Hex Editor.

**1) Navigate to the "Details" tab, what is the other filename and extension reported as present?**

Read and complete to find the other name of the hash seen.

**2) In the same "Details" tab, what is the reported compilation timestamp?**

This can be found as the creation time in the history section.

**3) What is the THM{} formatted flag on the report?**

Go to community to see what they have to say about the file.

## Task 7: Future Reading (References)

### Crypto & Checksums

[Cryptography & Network Security](https://dl.acm.org/doi/book/10.5555/1209579) - (Behrouz A. Forozuan., 2007)

[The first collision for full SHA-1](https://shattered.io/static/shattered.pdf) - (Stevens et al., 2017) / (Shattered.io)

[A Meaningful MD5 Hash Collision Attack](https://scholarworks.sjsu.edu/cgi/viewcontent.cgi?referer=https://www.google.com/&httpsredir=1&article=1020&context=etd_projects) - (Narayana D. Kashyap., 2008)

### cmnatic's blog

[So you want to analyze malware?](https://blog.cmnatic.co.uk/posts/so-you-want-to-analyse-malware/)

Feel free to reach out to me on [Twitter](https://twitter.com/R_G_9_n) if you have any questions.
