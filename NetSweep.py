from scapy.all import *
from sys import *
#from vpython import *
from PyQt5 import *

#def pingTest():



#def sniffer():



def getGateway():
    defGateway = conf.route.route("0.0.0.0")[2]
    return defGateway


#def findDevices():

#User should be able to choose a port or range of ports on a user selected IP and get a list of ports that are open or a list of all ports
def findOpenPort(destinationIP):

    #We declare this equal to 2 vars because it returns both answered and unanswered packets from the "send recieve" function as a tuple
    ans , unans = sr(IP(dst=destinationIP)/TCP(sport=RandShort(),dport=(0,65535),flags="S"),timeout=10)
    #ans.summary()

    #Below will return a list of all ports (RA = closed, SA = open)
    #ans.summary( lambda s,r: r.sprintf("%TCP.sport% \t %TCP.flags%") )

    #Below will filter to only the open ports
    ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s,r: r.sprintf("%TCP.sport% is open"))

def main():

    #getGateway test
    var = getGateway()
    print (var)

    findOpenPort(var)

if __name__ == "__main__":
    main()