from scapy.all import *
from scapy.all import IP, ICMP

def malformed_packet():
    try:
        # Attempt to send a malformed packet
        send(IP(dst="10.1.1.5", ihl=2, version=3) / ICMP())
        return "Successfully sent malformed packet"
    except Exception as e:
        # If an exception occurs while sending the packet, return a failure message
        return f"Failed to send packet: {str(e)}"

# Example usage
result = malformed_packet()
print(result)

#creates an IPv4 packet with the destination IP address set to "10.1.1.5".
#Additionally, it sets the IP header length (ihl) to 2 and the IP version (version) to 3.

#send() sends the packet over the network to the destination in the form of IP address