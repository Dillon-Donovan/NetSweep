from scapy.all import *

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

def main():
    subnet = input("Enter the subnet to scan (ex: 192.168.1.0): ")
    print(f"Scanning subnet {subnet}...")

    live_hosts = scan_subnet(subnet)

    print("Live hosts in the subnet:")
    for host in live_hosts:
        print(host)

if __name__ == "__main__":
    main()