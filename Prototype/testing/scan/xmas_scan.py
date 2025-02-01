from scapy.layers.inet import IP, TCP, sr1

def xmas_scan(target_ip, target_port):
    ip = IP(dst=target_ip)
    xmas = TCP(dport=target_port, flags="FPU")
    response = sr1(ip/xmas, timeout=1, verbose=0)

    if response:
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x14:
                print(f"Port {target_port} is CLOSED (Xmas scan)")
            elif response.getlayer(TCP).flags == 0x12:
                print(f"Port {target_port} is OPEN (Xmas scan)")
        else:
            print(f"Received unexpected response from {target_ip}")
    else:
        print(f"No response from {target_ip} on port {target_port}")


target_ip = "192.168.1.66"
target_port = 10004

xmas_scan(target_ip, target_port)