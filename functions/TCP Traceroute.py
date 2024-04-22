from scapy.all import *
from scapy.all import traceroute

def tcp_traceroute(default="www.google.com"):
    try:
        # Perform traceroute
        tcp_result, _ = traceroute(default, maxttl=20, l4=TCP(sport=RandShort()))

        # Format the traceroute results into a string
        tcp_output = ""
        for _, result in tcp_result:
            ip = result[IP].src
            tcp_output += f"Hop: {ip}\n"

        return tcp_output
    except Exception as e:
        return f"Error: {str(e)}"

# Test the function
print(tcp_traceroute())