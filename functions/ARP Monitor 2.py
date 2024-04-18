from scapy.all import *
from scapy.all import ARP

arp_request_count = 0
arp_request_cap = 10

print("Waiting for ARP Requests... ")
def arp_monitor_callback(pkt):
    global arp_request_count
    global arp_request_cap
    if ARP in pkt:
        if pkt[ARP].op == 1:  # ARP Request
            print("ARP Request: {src} is asking about {dst}".format(src=pkt[ARP].psrc, dst=pkt[ARP].pdst))
            arp_request_count +=1
        elif pkt[ARP].op == 2:  # ARP Reply
            print("ARP Reply: {src} has address {dst}".format(src=pkt[ARP].hwsrc, dst=pkt[ARP].psrc))

        if arp_request_count >= arp_request_cap:
            print("Stopping the ARP Monitoring") #stops the sniff
            raise KeyboardInterrupt #raises an exception

# Start the packet sniffer
sniff(prn=arp_monitor_callback, filter="arp", store=0)