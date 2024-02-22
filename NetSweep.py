from scapy.all import *
from sys import *
#from vpython import *
from PyQt5 import *

#def pingTest():



def sniffer(time,packetAmount=0):
    result = sniff(count=packetAmount,store=True,timeout=time)
    print("\nPackets sniffed:")
    result.summary()



def getGateway():
    defaultGateway = conf.route.route("0.0.0.0")[2]
    return defaultGateway


#def findDevices():

#User should be able to choose a port or range of ports on a user selected IP and get a list of ports that are open or a list of all ports
def findOpenPort(destinationIP,lower=0,upper=65535):

    print("\nFinding open ports on", destinationIP,"(Port range",lower,"-",upper,")")
    if(upper >= 15000):
        print("This may take a minute.")

    #We declare this equal to 2 vars because it returns both answered and unanswered packets from the "send recieve" function as a tuple
    ans , unans = sr(IP(dst=destinationIP)/TCP(sport=RandShort(),dport=(lower,upper),flags="S"),verbose=0,retry=-1,timeout=1)
    
    print("Answered packets =",len(ans))
    print("Unanswered packets =",len(unans))
    print("\nThese ports are open on", destinationIP)
    ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: r.sprintf("%TCP.sport% is open"))

    #Below line will print full return 
    #ans.summary()
    #unans.summary()

    #Below will return a list of all ports (RA = closed, SA = open)
    #ans.summary( lambda s,r: r.sprintf("%TCP.sport% \t %TCP.flags%") )
    #unans.summary( lambda s: s.sprintf("%TCP.sport%"))

    #Below will filter to only the open ports
    #ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: r.sprintf("%TCP.sport% is open"))

def main():

    #getGateway() test
    myGateway = getGateway()
    print(("Current gateway is"), myGateway)

    #findOpenPort() test //findOpenPort(%DestinationIP%,%LowerBound%,%UpperBound%) //Defaults - [%LowerBound% = 0],[%UpperBound% = 65535(all ports)]
    findOpenPort(myGateway,0,5000)

    #sniffer() test //sniffer(%Time%,%PacketLimit%) //Defaults - [%PacketLimit% = 0(infinite)]
    sniffer(5,5)


if __name__ == "__main__":
    main()