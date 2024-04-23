from scapy.all import *

destination_ip = "8.8.8.8" #IP adresss of google
destination_port = 80 #port 80 is HTTP
gateway_ip = "192.168.1.1"

#creation of packet to send to public service
packet = IP(dst=gateway_ip)/TCP(dport=destination_port) #i need to have gateway addressed here somehow for it to work
packet2 = IP(dst=destination_ip)/TCP(dport=destination_port)
print("Your packet is displayed as: ", packet)
print("and packet 2: ", packet2)

#send the TCP packet and receive response
response = sr1(packet, timeout=2)
response = sr1(packet2, timeout=2)

#check if a response is received
if response:
    print("Public IP address seen through NAT:", response.src)
else:
    print("No response received.")

