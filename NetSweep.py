from scapy.all import *
from sys import *
#from vpython import *
from PyQt5 import *

#def pingTest():

#DNS Requests
ans = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname="secdev.org",qtype="A")))
print(ans.an[0].rdata)

#for troubleshooting misconfigurations with DNS and DNS cache poisoning attacks
def dns_lookup(domain="myip.opendns.com", dns_server="resolver1.opendns.com"):
    # Create DNS query packet
    query_packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))

    # Send DNS query and receive response
    response = sr1(query_packet, verbose=False)

    # Processing response
    if response and response.haslayer(DNS):
        for answer in response[DNS].an:
            if answer.type == 1:  # IPv4 address record
                print("IP Address:", answer.rdata)
    else:
        print("DNS query failed or no response received")

def scan_subnet(subnet = conf.route.route("0.0.0.0")[2]):
    # Define the network range to scan
    ip_range = subnet + "/24"

    # Initialize an empty list to store live hosts
    live_hosts = []

    # Craft ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # Send and receive packets
    ans, _ = srp(arp_request, timeout=2, verbose=False)

    # Process responses
    for sent, received in ans:
        live_hosts.append(received)

    return live_hosts

def sniffer(time,packetAmount=0):
    result = sniff(count=packetAmount,store=True,timeout=time)
    #print("\nPackets sniffed:")
    #result.summary()
    return result



def getGateway():
    defaultGateway = conf.route.route("0.0.0.0")[2]
    return defaultGateway


#def findDevices():

#User should be able to choose a port or range of ports on a user selected IP and get a list of ports that are open or a list of all ports
def findOpenPort(destinationIP,lower=0,upper=65535):

    print("\nFinding open ports on", destinationIP,"(Port range",lower,"-",upper,")")
    if(upper >= 15000):
        print("This may take a minute.")

    #We declare this equal to 2 vars because it returns both answered and unanswered packets from the "send recieve" function as a tuple
    ans , unans = sr(IP(dst=destinationIP)/TCP(sport=RandShort(),dport=(lower,upper),flags="S"),verbose=0,retry=-1,timeout=1)
    
    print("Answered packets =",len(ans))
    print("Unanswered packets =",len(unans))
    print("\nThese ports are open on", destinationIP)
    ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: r.sprintf("%TCP.sport% is open"))

    #Below line will print full return 
    #ans.summary()
    #unans.summary()

    #Below will return a list of all ports (RA = closed, SA = open)
    #ans.summary( lambda s,r: r.sprintf("%TCP.sport% \t %TCP.flags%") )
    #unans.summary( lambda s: s.sprintf("%TCP.sport%"))

    #Below will filter to only the open ports
    #ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: r.sprintf("%TCP.sport% is open"))

#def main():
    #getGateway() test
    #myGateway = getGateway()
    #print(("Current gateway is"), myGateway)

    #findOpenPort() test //findOpenPort(%DestinationIP%,%LowerBound%,%UpperBound%) //Defaults - [%LowerBound% = 0],[%UpperBound% = 65535(all ports)]
    #findOpenPort(myGateway,0,5000)

    #sniffer() test //sniffer(%Time%,%PacketLimit%) //Defaults - [%PacketLimit% = 0(infinite)]
    #sniffer(5,5)
