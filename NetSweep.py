from scapy.all import *
from sys import *
from PyQt5 import *
import subprocess
import socket



#DNS Requests
#ans = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname="secdev.org",qtype="A")))
#print(ans.an[0].rdata)

#For troubleshooting misconfigurations with DNS and DNS cache poisoning attacks
def dns_lookup(domain="myip.opendns.com", dns_server="resolver1.opendns.com"):
    #Create DNS query packet
    query_packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))

    #Send DNS query and receive response
    response = sr1(query_packet, verbose=False)

    #Processing response
    if response and response.haslayer(DNS):
        for answer in response[DNS].an:
            if answer.type == 1:
                print("IP Address:", answer.rdata)
    else:
        print("DNS query failed or no response received")
    return response

#Public IP function
def public_ip(domain, dns_server="resolver1.opendns.com"):
    # Create DNS query packet
    query_packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))

    # Send DNS query and receive response
    response = sr1(query_packet, verbose=False)

    # Processing response
    if response and response.haslayer(DNS):
        print("Domain:", domain)
        for answer in response[DNS].an:
            if answer.type == 1:  # IPv4 address record
                print("IP Address:", answer.rdata)
    else:
        print("DNS query failed or no response received")

    return public_ip("myip.opendns.com")

def getGateway():
    defaultGateway = conf.route.route("0.0.0.0")[2]
    return defaultGateway

def icmp_ping(ipAddress = getGateway()):
    pingOutput = []
    try:
        ans, unans = sr(IP(dst=ipAddress)/ICMP(), timeout=3, chainEX=True)
    except:
        return "Please enter valid IP address."
    for sent, recieved in ans:
        pingOutput.append(recieved)
    return pingOutput

def tcp_traceroute(default="www.google.com"):
    try:
        # Perform traceroute
        tcp_result, _ = traceroute(default, maxttl=20, l4=TCP(sport=RandShort()))

        # Format the traceroute results into a string
        tcp_output = ""
        for _, result in tcp_result:
            ip = result[IP].src
            tcp_output += f"Hop: {ip}\n"

        return tcp_output
    except Exception as e:
        return f"Error: {str(e)}"

# ARP Monitor uses two functions, one extra for callback
def arp_monitor():
    arp_results = []

    # Callback function to process ARP packets
    def callback(pkt):
        if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
            arp_results.append(pkt.sprintf("%ARP.hwsrc% sends ARP request to %ARP.pdst%"))
            print(pkt.sprintf("%ARP.hwsrc% sends ARP request to %ARP.pdst%"))  # Print each request as it comes

    # Sniff ARP packets until 3 requests are captured
    while len(arp_results) < 3:
        sniff(prn=callback, filter="arp", count=1)
        #print("\n")  # newline -- may not need

    return arp_results

#Subnet Scan
def scan_subnet(subnet = getGateway()):
    #Define the network range to scan
    ip_range = subnet + "/24"
    live_hosts = []

    #Craft ARP packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    #Send packets
    ans, _ = srp(arp_request, timeout=2, verbose=False)

    #Responses
    for sent, received in ans:
        live_hosts.append(received)
    return live_hosts

#Malformed Packet
def malformed_packet():
    try:
        # Attempt to send a malformed packet
        send(IP(dst="10.1.1.5", ihl=2, version=3) / ICMP())
        return "Successfully sent malformed packet"
    except Exception as e:
        # If an exception occurs while sending the packet, return a failure message
        return f"Failed to send packet: {str(e)}"
    
#Sniffer
def sniffer(time,packetAmount=0):
    result = sniff(count=packetAmount,store=True,timeout=time)
    return result

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

#Execute "ipconfig /all" command and return output
def get_ipconfig():
    ipconfig_output = subprocess.getoutput('ipconfig /all')
    return  ipconfig_output