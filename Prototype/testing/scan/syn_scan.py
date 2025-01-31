from scapy.all import send
from scapy.layers.inet import IP, TCP, sr1

def syn_scan(target_ip, start_port, end_port):
    for target_port in range(start_port, end_port + 1):
        ip = IP(dst=target_ip)
        syn = TCP(dport=target_port, flags="S")
        response = sr1(ip/syn, timeout=1, verbose=0)

        if response:
            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    print(f"Port {target_port} is OPEN (SYN scan)")
                    rst = TCP(dport=target_port, flags="R")
                    send(ip/rst, verbose=0)
                elif response.getlayer(TCP).flags == 0x14:
                    print(f"Port {target_port} is CLOSED (SYN scan)")
        else:
            print(f"No response from {target_ip} on port {target_port}")


target_ip = "192.168.56.1"
start = 10000
end = 10011

syn_scan(target_ip, start, end)