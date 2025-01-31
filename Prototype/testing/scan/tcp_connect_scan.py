from scapy.all import send
from scapy.layers.inet import IP, TCP, sr1

def tcp_connect_scan(target_ip, start, end):
    for target_port in range(start, end + 1):
        ip = IP(dst=target_ip)
        syn = TCP(dport=target_port, flags="S")
        response = sr1(ip/syn, timeout=1, verbose=0)

        if response:
            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    print(f"Port {target_port} is OPEN (TCP Connect Scan)")
                    ack = TCP(dport=target_port, flags="A", seq=response.seq + 1, ack=response.ack)
                    send(ip/ack, verbose=0)
                elif response.getlayer(TCP).flags == 0x14:
                    print(f"Port {target_port} is CLOSED (TCP Connect Scan)")
        else:
            print(f"No response from {target_ip} on port {target_port}")


target_ip = "192.168.56.1"
start = 10000
end = 10011

tcp_connect_scan(target_ip, start, end)