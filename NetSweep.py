from scapy.all import *
from sys import *
from PyQt5 import *
import subprocess
import socket

#Gets users public IP information via DNS request
def public_ip(domain = "myip.opendns.com", dns_server="resolver1.opendns.com", timeout=10):
    #Create DNS query packet
    try:
        if domain == "myip.opendns.com":
            query_packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        else:
            query_packet = IP(dst="1.1.1.1") / UDP() / DNS(rd=1, qd=DNSQR(qname=domain))

        #Send DNS query and receive response with a timeout
        response = sr1(query_packet, timeout=timeout, verbose=False)

        #Log/Build output
        if response and response.haslayer(DNS):
            for answer in response[DNS].an:
                if answer.type == 1:
                    return answer.rdata
        else:
            return "No response recieved"
    except:
        return "Error parsing domain"

#Function to get users default gateway
def getGateway():
    defaultGateway = conf.route.route("0.0.0.0")[2]
    return defaultGateway

#Pings provided IP and gateway if no IP provided
def icmp_ping(ipAddress = getGateway()):
    pingOutput = []

    #Send request catch IP errors
    try:
        ans, unans = sr(IP(dst=ipAddress)/ICMP(), timeout=3, chainEX=True)
    except:
        return "Please enter valid IP address."

    #Log/Build output
    for sent, recieved in ans:
        pingOutput.append(recieved)
    return pingOutput

#Sends packets and returns the route taken to reach the provided IP
def tcp_traceroute(default="www.google.com"):
    tcp_packets = []

    #Perform traceroute
    tcp_result, _ = traceroute(default, maxttl=20, l4=TCP(sport=RandShort()))

    #Log/Build output
    for sent, received in tcp_result:
        tcp_packets.append(received)
    return tcp_packets
        
#ARP Monitor uses two functions, one extra for callback
def arp_monitor():
    arp_results = []

    #Callback function to process ARP packets
    def callback(pkt):
        if ARP in pkt and pkt[ARP].op in (1, 2):
            arp_results.append(pkt.sprintf("%ARP.hwsrc% sends ARP request to %ARP.pdst%"))
            print(pkt.sprintf("%ARP.hwsrc% sends ARP request to %ARP.pdst%"))

    #Sniff ARP packets until 3 requests are captured
    while len(arp_results) < 3:
        sniff(prn=callback, filter="arp", count=1)
    return arp_results

#Scans subnet for other hosts
def scan_subnet(subnet = getGateway()):
    #Define the network range to scan
    ip_range = subnet + "/24"
    live_hosts = []

    #Create base ARP packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    #Send packets
    ans, _ = srp(arp_request, timeout=2, verbose=False)

    #Log responses
    for sent, received in ans:
        live_hosts.append(received)
    return live_hosts

#Malformed Packet
def malformed_packet():
    try:
        #Attempt to send a malformed packet
        send(IP(dst="10.1.1.5", ihl=2, version=3) / ICMP())
        return "Successfully sent malformed packet"
    except Exception as e:
        #If an exception occurs while sending the packet, return a failure message
        return f"Failed to send packet: {str(e)}"
    
#Sniffs based on set time or packet amount
def sniffer(time,packetAmount=0):
    result = sniff(count=packetAmount,store=True,timeout=time)
    return result

#Scans ports between upper and lower on destination IP
def scanPorts(destinationIP = getGateway(),lower="0",upper="65535"):
    open_ports = []
    
    for port in range(int(lower), int(upper) + 1):
        packet = IP(dst=destinationIP) / TCP(sport=RandShort(), dport=port, flags="S")
        ans, unans = sr(packet, verbose=0, retry=1, timeout=1)
            
        #Check if there's an answer and if the TCP flag is SA (SYN-ACK)
        if ans and ans[0][1].haslayer(TCP) and ans[0][1][TCP].flags == 0x12:
            open_ports.append(port)
    return open_ports

#Execute "ipconfig /all" command and return output as string
def ipconfig():
    ipconfig_output = subprocess.getoutput('ipconfig /all')
    return  ipconfig_output