from scapy.all import *
from scapy.all import Ether

def scan_subnet(subnet):
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