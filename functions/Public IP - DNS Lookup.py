from scapy.all import *
from scapy.all import UDP, DNS, DNSQR, IP

#DNS Requests
ans = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname="secdev.org",qtype="A")))
print(ans.an[0].rdata)

#for troubleshooting misconfigurations with DNS and DNS cache poisoning attacks

def public_ip(domain = "myip.opendns.com", dns_server="resolver1.opendns.com", timeout=10):
    # Create DNS query packet
    query_packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))

    # Send DNS query and receive response with a timeout
    response = sr1(query_packet, timeout=timeout, verbose=False)

    # Processing response
    if response and response.haslayer(DNS):
        for answer in response[DNS].an:
            if answer.type == 1:  # IPv4 address record
                return answer.rdata
    else:
        return None
    
print(public_ip())



