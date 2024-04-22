from scapy.all import *
from scapy.all import UDP, DNS, DNSQR, IP

#DNS Requests
ans = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname="secdev.org",qtype="A")))
print(ans.an[0].rdata)

#for troubleshooting misconfigurations with DNS and DNS cache poisoning attacks

def dns_lookup(domain, dns_server="resolver1.opendns.com"):
    # Create DNS query packet
    query_packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))

    # Send DNS query and receive response
    response = sr1(query_packet, verbose=False)

    # Process response
    if response and response.haslayer(DNS):
        print("Domain:", domain)
        for answer in response[DNS].an:
            if answer.type == 1:  # IPv4 address record
                print("IP Address:", answer.rdata)
    else:
        print("DNS query failed or no response received")

# example:
print (dns_lookup("myip.opendns.com"))
