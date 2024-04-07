from scapy.all import *

def sniff_wireless_packets(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            # Management Frame subtype 8 represents Beacon frame
            print("Wireless device found: " + pkt.addr2)

def main():
    # Start sniffing wireless packets on the specified interface
    sniff(iface="Intel(R) Dual Band Wireless-AC 8265", prn=sniff_wireless_packets, store=0)

if __name__ == "__main__":
    main()