from scapy.all import *
from scapy.all import traceroute

traceroute(["www.yahoo.com","www.altavista.com","www.wisenut.com","www.copernic.com"],maxttl=20)