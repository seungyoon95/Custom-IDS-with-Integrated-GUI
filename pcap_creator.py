from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.utils import wrpcap


def create_syn_flood():
    packets = []
    for _ in range(1000):
        packet = IP(dst="192.168.1.1") / TCP(dport=8900, flags="S")
        packets.append(packet)

    wrpcap("./pcaps/syn_flood.pcap", packets)


def create_udp_flood():
    packets = []
    for _ in range(1000):
        packet = IP(dst="192.168.1.1") / UDP(dport=8900)
        packets.append(packet)

    wrpcap("./pcaps/udp_flood.pcap", packets)


def create_icmp_flood():
    packets = []
    for _ in range(1000):
        packet = IP(dst="192.168.1.1") / ICMP()
        packets.append(packet)

    wrpcap("./pcaps/icmp_flood.pcap", packets)


def create_syn_scan():
    packets = []
    for port in range(1000, 1010):
        packet = IP(dst="192.168.1.1") / TCP(dport=port, flags="S")
        packets.append(packet)

    wrpcap("./pcaps/syn_scan.pcap", packets)


def create_tcp_connect_scan():
    packets = []
    for port in range(1000, 1010):
        syn_packet = IP(dst="192.168.1.1") / TCP(dport=port, sport=8900, flags="S", seq=1000)
        packets.append(syn_packet)
        
        syn_ack_packet = IP(src="192.168.1.1", dst="192.168.1.66") / TCP(dport=8900, sport=port, flags="SA", seq=2000, ack=1001)
        packets.append(syn_ack_packet)

        ack_packet = IP(dst="192.168.1.1") / TCP(dport=port, sport=8900, flags="A", seq=1001, ack=2001)
        packets.append(ack_packet)

    wrpcap("./pcaps/tcp_connect_scan.pcap", packets)


def create_xmas_scan():
    packet = IP(dst="192.168.1.1") / TCP(dport=8900, flags="FPU")

    wrpcap("./pcaps/xmas_scan.pcap", packet)


def create_null_scan():
    packet = IP(dst="192.168.1.1") / TCP(dport=8900, flags="")

    wrpcap("./pcaps/null_scan.pcap", packet)


def create_dns_spoof():
    packet = IP(dst="192.168.1.1", src="8.8.8.8") / UDP(dport=53, sport=53) / DNS(
    id=1234, qr=1, aa=1, qd=DNSQR(qname="www.example.com"), 
    an=DNSRR(rrname="www.example.com", rdata="5.5.5.5")
    )
    wrpcap("./pcaps/dns_spoof.pcap", packet)


def create_arp_spoof():
    packet = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
    wrpcap("./pcaps/arp_spoof.pcap", packet)


def create_ssh_brute_force():
    packets = []
    for i in range(50):
        syn_packet = IP(dst="192.168.1.1") / TCP(dport=22, sport=8900, flags="S", seq=1000+i)
        packets.append(syn_packet)

        syn_ack_packet = IP(src="192.168.1.1", dst="192.168.1.100") / TCP(dport=8900, sport=22, flags="SA", seq=2000+i, ack=1001+i)
        packets.append(syn_ack_packet)

        ack_packet = IP(dst="192.168.1.1") / TCP(dport=22, sport=8900, flags="A", seq=1001+i, ack=2001+i)
        packets.append(ack_packet)

        ssh_login_packet = IP(dst="192.168.1.1") / TCP(dport=22, sport=8900, flags="P") / Raw(load=f"SSH-2.0-username:admin{i},password:pass{i}")
        packets.append(ssh_login_packet)

        ssh_response_packet = IP(src="192.168.1.1", dst="192.168.1.100") / TCP(dport=8900, sport=22, flags="P") / Raw(load="Authentication failed")
        packets.append(ssh_response_packet)

    # Save packets to a PCAP file
    wrpcap("./pcaps/ssh_brute_force.pcap", packets)


def create_command_injection():
    packet = IP(dst="192.168.1.1") / TCP(dport=80) / Raw(load="GET /?cmd=cat /etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n")
    wrpcap("./pcaps/command_injection.pcap", packet)


def create_sql_injection():
    packet = IP(dst="192.168.1.1") / TCP(dport=80) / Raw(load="GET /login.php?user=admin'-- HTTP/1.1\r\nHost: example.com\r\n\r\n")
    wrpcap("./pcaps/sql_injection.pcap", packet)


def create_pcap_files():
    create_syn_flood()
    create_udp_flood()
    create_icmp_flood()
    create_syn_scan()
    create_tcp_connect_scan()
    create_xmas_scan()
    create_null_scan()
    create_dns_spoof()
    create_arp_spoof()
    create_ssh_brute_force()
    create_command_injection()
    create_sql_injection()


def main():
    create_pcap_files()


if __name__ == "__main__":
    main()
