from scapy.all import *
from scapy.all import ICMP

ans, unans = sr(IP(dst="10.0.0.1")/ICMP(), timeout=3)
ans.summary(lambda s,r: r.sprintf("%IP.src% is alive") )