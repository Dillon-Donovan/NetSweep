from scapy.all import *
from scapy.all import ARP

print("Waiting for ARP Requests... ")
def arp_monitor_callback(pkt):
    if ARP in pkt:
        if pkt[ARP].op == 1:  # ARP Request
            print("ARP Request: {src} is asking about {dst}".format(src=pkt[ARP].psrc, dst=pkt[ARP].pdst))
        elif pkt[ARP].op == 2:  # ARP Reply
            print("ARP Reply: {src} has address {dst}".format(src=pkt[ARP].hwsrc, dst=pkt[ARP].psrc))

# Start the packet sniffer
sniff(prn=arp_monitor_callback, filter="arp", store=0)