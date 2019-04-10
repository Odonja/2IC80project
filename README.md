# 2IC80project
This is the code for the lab project of course 2IC80 for group 34 Nameless

Both the arppoisoner and dnspoisoner are only for use on linux

To use the arppoisoner type the following on the command line:
sudo python ./arppoisoner.py victims.txt servers.txt MTM timeBetweenPackages
and for the MTM type the following command line:
sudo nano /proc/sys/net/ipv4/ip_forward where you have to substitute the 0 with a 1, press ctrl-x and y + enter to save

victims.txt and server.txt contain the IP addresses each on a new line, for example:  
1.1.1.1  
1.1.1.2  
1.1.1.3  

MTM is the IP address of the system that should become the man-in-the-middle

timeBetweenPackages:
- if negative the arppoisoner will send the spoofed messages only once
- if positive it is the time between when 2 the same spoofed messages will be send

The arp poisoner will poison the ARP caches of the victims and servers such that all communication of any combination of 
victim and server will go via the MTM.

---------------------------------------------------------------------------------------------------------------------------

To use the arppoisoner type the following on the command line:
sudo python ./dnspoisoner.py victims.txt victimDnsServerIp sitesToBeSpoofed.txt myIp myMAC
and:
sudo nano /proc/sys/net/ipv4/ip_forward where you have to substitute the 0 with a 1, press ctrl-x and y + enter to save

victims.txt contains the IP addresses each on a new line, for example:
1.1.1.1
1.1.1.2
1.1.1.3

victimDnsServerIp is the IP of the DNS server you are pretending to be

sitesToBeSpoofed.txt contains the sites and the IP addresses you want the victims to be directed to seperated by a space, for example:  
google.com 1.1.1.1  
www.google.com 1.1.1.1  
buienradar.nl 1.1.1.2  

myIp myMAC are the IP and the MAC of the system the tool is used upon

The dns poisoner will poison the cache of the victims such that traffic to the DNS server now is send to the attacker, 
the attacker will forward the messages to the DNS server and reply to the victim for the sites that are in sitesToBeSpoofed.txt
with a spoofed message. 
