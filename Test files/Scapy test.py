import sys
from scapy.all import *

#Traceroute test
#scapy.traceroute("1.1.1.1")

#ARP test
#scapy.arping("173.219.205.30")

#ARP test rang xxx.xxx.0-255
#scapy.arping("192.168.0.5 1/24")

#Variable for target IP 1/16 denotes xxx.xxx.0-255.0-255
target_ip = "192.168.0.1/16"

#Make an ARP packet and store it
arp = ARP(pdst=target_ip)

#Creat ether packet
#ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

#Stack them to create one packet
packet = ether/arp

#Query the network using new ARP packet
result = srp(packet, timeout=3, verbose=0)[0]

#Create a list of clients
clients = []

#For each response, append ip and mac address to clients list
for sent, received in result:
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

#Loop through and print the new list
print("Available devices in the network:")
print("IP" + " "*18+"MAC")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))