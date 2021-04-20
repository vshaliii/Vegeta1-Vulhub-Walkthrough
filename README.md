# Vegeta:1 ~Vulhub Walkthrough

Here's walkthrough of vulhub machine. This machine is for complete beginners. We need to find flag root.txt.

## Scanning

**nmap -p- 192.168.122.130**

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled.png)

**nmap -sV -A 192.168.122.130 (Service version scan)**

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%201.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%201.png)

**nmap -sV -A --script vuln 192.168.122.130 (Vulnerability scanning)**

```jsx
root@kali:~# nmap -sV -A --script vuln 192.168.122.130
Starting Nmap 7.80SVN ( https://nmap.org ) at 2020-08-19 01:15 EDT
Nmap scan report for 192.168.122.130
Host is up (0.00039s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/admin.php: Possible admin folder
|   /login.php: Possible admin folder
|   /robots.txt: Robots file
|   /image/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
|   /img/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
|_  /manual/: Potentially interesting folder
|_http-server-header: Apache/2.4.38 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.38: 
|     	CVE-2020-11984	7.5	https://vulners.com/cve/CVE-2020-11984
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
|     	CVE-2019-10097	6.0	https://vulners.com/cve/CVE-2019-10097
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	CVE-2019-0215	6.0	https://vulners.com/cve/CVE-2019-0215
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	CVE-2020-9490	5.0	https://vulners.com/cve/CVE-2020-9490
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-10081	5.0	https://vulners.com/cve/CVE-2019-10081
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
|     	CVE-2019-0197	4.9	https://vulners.com/cve/CVE-2019-0197
|     	CVE-2020-11993	4.3	https://vulners.com/cve/CVE-2020-11993
|_    	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
MAC Address: 00:0C:29:08:B4:25 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.39 ms 192.168.122.130

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.93 seconds
root@kali:~#
```

whatweb [http://192.168.122.130](http://192.168.122.130) (to identify cms)

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%202.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%202.png)

**nikto -h http://192.168.122.130/**

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%203.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%203.png)

**gobuster -u [http://192.168.122.130](http://192.168.122.130) -w /usr/share/wordlists/rockyou.txt**

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%204.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%204.png)

**Found some directories**

## Enumeration

Open url in browser

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%205.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%205.png)

Found directory find_me in robots.txt

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%206.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%206.png)

Accessing find_me

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%207.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%207.png)

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%208.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%208.png)

Checking view-source

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%209.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%209.png)

Found base64 string in comment

Decoding string using base64 decoder and found another base64 string

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2010.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2010.png)

Now decoding base64 to image and we found QR code

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2011.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2011.png)

After reading qr code we found some password topshellv

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2012.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2012.png)

Accessing directory /bulmu

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2013.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2013.png)

It contains an audio file. I listen to the wave file and it sounds like Morse code.

Decoding morse audio into text

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2014.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2014.png)

And we found another user and password

## Exploitation

Login using ssh

ssh trunks@192.168.122.130

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2015.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2015.png)

**Successfully connected

## Privilege escalation

Checking permission of /etc/passwd

ls -al /etc/passwd

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2016.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2016.png)

User trunks have permission to write in /etc/passwd

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2017.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2017.png)

Lets change password of root and login 

su - root

ls 

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2018.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2018.png)

*** Successfully Found flag root.txt

cat root.txt

![Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2019.png](Vegeta%201%20~Vulnhub%20Walkthrough%20c4c724b3fb9249e38a5da049023cf476/Untitled%2019.png)
