from scapy.all import *
from scapy.all import ARP


from scapy.all import *

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
        print("\n")  # Add a newline after each ARP request

    return arp_results

# Example usage
arp_results = arp_monitor()
print(arp_results)

# Example usage
arp_results = arp_monitor()
print(arp_results)