from scapy.all import *
from scapy.all import IP, ICMP

send(IP(dst="10.1.1.5", ihl=2, version=3)/ICMP())


#creates an IPv4 packet with the destination IP address set to "10.1.1.5".
#Additionally, it sets the IP header length (ihl) to 2 and the IP version (version) to 3.

#send() sends the packet over the network to the destination in the form of IP address