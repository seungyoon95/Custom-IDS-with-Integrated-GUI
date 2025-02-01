import constants

from datetime import datetime
import time
import os
import socket
import re
from collections import defaultdict, deque

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSRR

# Dictionaries to hold packet counts from 
syn_count = defaultdict(list)
udp_count = defaultdict(list)
icmp_count = defaultdict(list)

# Keeping a list of IP addresses that already generated an alert about certain attack to avoid spamming
syn_flood_alerted = set()
udp_flood_alerted = set()
icmp_flood_alerted = set()

ping_of_death_alerted = set()

pending_handshake = defaultdict(deque)

completed_handshake = {}
syn_scans = {}

arp_table = {}
dns_records = {}
ssh_count = {}
ssh_payloads = {}

ip_whitelist = set()

# Host IP address
local_ip = socket.gethostbyname(socket.gethostname())

# Writes packet info to a log file
def write_to_log(attack_type, packet, info=None):
    print("\n===========================================")
    print(datetime.now())
    print(f"Attack Type: {attack_type}")

    if info == "TCP" and type(info) != set:
        print(f"Source IP and Port: {packet[IP].src}:{packet[TCP].sport}")
        print(f"Destination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
    if info == "UDP":
        print(f"Source IP and Port: {packet[IP].src}:{packet[UDP].sport}")
        print(f"Destination IP and Port: {packet[IP].dst}:{packet[UDP].dport}")
    if info == "ICMP":
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
    if (attack_type == "SYN SCAN" or attack_type == "TCP CONNECT SCAN") and type(info) == list:
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"List of scanned ports: {info}")
    
    if attack_type == "ARP SPOOF":
        print(f"Source Mac Address: {info}")
    if attack_type == "DNS SPOOF":
        print(f"Affected Domain: {info}")
    if attack_type == "SSH BRUTE FORCE":
        print("Brute Force detected:")
        for payload in info:
            print(payload)
    if attack_type == "COMMAND INJECTION":
        print(f"Command Detected: {info}")
    if attack_type == "SQL INJECTION":
        print(f"Command Detected: {info}")
    
    

    current_date = datetime.now().strftime('%Y-%m-%d')

    # Creating log directory if it doesn't already exist
    log_directory = './logs'
    os.makedirs(log_directory, exist_ok=True)

    filename = f"{log_directory}/{current_date}.log"

    with open(filename, 'a') as f:
        if os.stat(filename).st_size != 0:
            f.write('\n')
        # f.write(packet.summary())
        f.write("===========================================\n")
        f.write(str(datetime.now()))
        f.write(f"\nAttack Type: {attack_type}")
        if info == "TCP" and type(info) != set:
            f.write(f"\nSource IP and Port: {packet[IP].src}:{packet[TCP].sport}")
            f.write(f"\nDestination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
        if info == "UDP":
            f.write(f"\nSource IP and Port: {packet[IP].src}:{packet[UDP].sport}")
            f.write(f"\nDestination IP and Port: {packet[IP].dst}:{packet[UDP].dport}")
        if info == "ICMP":
            f.write(f"\nSource IP: {packet[IP].src}")
            f.write(f"\nDestination IP: {packet[IP].dst}")
        if (attack_type == "SYN SCAN" or attack_type == "TCP CONNECT SCAN") and type(info) == list:
            f.write(f"\nSource IP: {packet[IP].src}")
            f.write(f"\nDestination IP: {packet[IP].dst}")
            f.write(f"\nList of scanned ports: {info}")
        
        if attack_type == "ARP SPOOF":
            f.write(f"\nSource Mac Address: {info}")
        if attack_type == "ARP SPOOF":
            f.write(f"\nAffected Domain: {info}")
        if attack_type == "SSH BRUTE FORCE":
            f.write("\nBrute Force Attack Detected:")
            for payload in info:
                f.write("\npayload")
        if attack_type == "COMMAND INJECTION":
           f.write(f"\nCommand Detected: {info}")
        if attack_type == "SQL INJECTION":
            f.write(f"\nCommand Detected: {info}")
    

def ip_whitelisting(ip_address):
    if ip_address is not None and ip_address not in ip_whitelist:
        ip_whitelist.add(ip_address)
        print(f"IP: {ip_address} added to the whitelist")

    return ip_whitelist


# Detects SYN Flood Attack based on given timeframe and threshold
def syn_flood(packet, ip_whitelist):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        source_ip = packet[IP].src
        dst_ip = packet[IP].dst

        current_time = time.time()

        if source_ip not in ip_whitelist:
            if packet[TCP].flags == 'S':
                syn_count[source_ip].append(current_time)
                syn_count[source_ip] = [t for t in syn_count[source_ip] if current_time - t < constants.TIMEFRAME]

                pending_handshake[(source_ip, dst_ip)].append(current_time)

                while pending_handshake[(source_ip, dst_ip)] and current_time - pending_handshake[(source_ip, dst_ip)][0] > constants.TIMEFRAME:
                    pending_handshake[(source_ip, dst_ip)].popleft()

                if len(syn_count[source_ip]) > constants.FLOOD_THRESHOLD or len(pending_handshake[(source_ip, dst_ip)]) > constants.MAX_PENDING:
                    if source_ip != local_ip and source_ip not in syn_flood_alerted:
                        write_to_log("SYN FLOOD", packet, "TCP")
                        syn_flood_alerted.add(source_ip)

            elif packet[TCP].flags == 'A':
                if (source_ip, dst_ip) in pending_handshake:
                    if pending_handshake[(source_ip, dst_ip)]:
                        pending_handshake[(source_ip, dst_ip)].popleft()    
                

# Detects UDP Flood Attack based on given timeframe and threshold
def udp_flood(packet, ip_whitelist):
    if packet.haslayer(UDP) and packet.haslayer(IP):
        whitelisted_port = [53, 80, 123, 443]

        source_ip = packet[IP].src
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        current_time = time.time()

        udp_count[source_ip].append(current_time)
        udp_count[source_ip] = [t for t in udp_count[source_ip] if current_time - t < constants.TIMEFRAME]

        if source_ip not in ip_whitelist and src_port not in whitelisted_port and dst_port not in whitelisted_port:
            if len(udp_count[source_ip]) > constants.FLOOD_THRESHOLD:
                if source_ip != local_ip and source_ip not in udp_flood_alerted:
                    write_to_log("UDP FLOOD", packet, "UDP")
                    udp_flood_alerted.add(source_ip)


# Detects ICMP Flood Attack based on given timeframe and threshold
def icmp_flood(packet, ip_whitelist):
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        source_ip = packet[IP].src
        current_time = time.time()

        if source_ip not in ip_whitelist:
            icmp_count[source_ip].append(current_time)
            icmp_count[source_ip] = [t for t in icmp_count[source_ip] if current_time - t < constants.TIMEFRAME]

            if len(icmp_count[source_ip]) > constants.FLOOD_THRESHOLD:
                if source_ip != local_ip and source_ip not in ip_whitelist and source_ip not in icmp_flood_alerted:
                    write_to_log("ICMP FLOOD", packet, "ICMP")
                    icmp_flood_alerted.add(source_ip)


def ping_of_death(packet, ip_whitelist):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        source_ip = ip_layer.src

        # Check if the packet is fragmented
        if ip_layer.flags == 1:
            reassembled_packet = b""
            while reassembled_packet.haslayer(IP) and reassembled_packet[IP].flags == 1:
                reassembled_packet += packet[IP].payload
                packet = packet[IP].payload
            reassembled_packet += packet[IP].payload
            total_size = len(reassembled_packet)
        else:
            total_size = len(packet)

        if total_size > 65535 and source_ip not in ip_whitelist:
            write_to_log("PING OF DEATH", packet, "ICMP")


def type_flood(packet, ip_whitelist):
    syn_flood(packet, ip_whitelist)
    udp_flood(packet, ip_whitelist)
    icmp_flood(packet, ip_whitelist)
    ping_of_death(packet, ip_whitelist)


def tcp_connect_scan(packet, ip_whitelist):
    whitelisted_port = [22, 53, 443]
    if packet.haslayer(TCP) and packet.haslayer(IP):
        source_ip = packet[IP].src
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        current_time = time.time()

        if packet[TCP].flags == "A":
            if source_ip not in completed_handshake:
                completed_handshake[source_ip] = {}

            completed_handshake[source_ip][dst_port] = current_time

            completed_handshake[source_ip] = {
                port: timestamp
                for port, timestamp in completed_handshake[source_ip].items()
                if current_time - timestamp <= constants.TIMEFRAME
            }

            if source_ip in syn_scans:
                syn_scans.pop(source_ip, None)

            if len(completed_handshake[source_ip]) > constants.SCAN_THRESHOLD:
                if source_ip not in ip_whitelist and src_port not in whitelisted_port  and dst_port not in whitelisted_port:
                    write_to_log("TCP CONNECT SCAN", packet, list(completed_handshake[source_ip].keys()))


def syn_scan(packet, ip_whitelist):
    whitelisted_port = [22, 53, 443]
    current_time = time.time()

    if packet.haslayer(TCP) and packet[TCP].flags == "S":
            source_ip = packet[IP].src
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
                       
            if source_ip not in syn_scans:
                syn_scans[source_ip] = {}

            syn_scans[source_ip][dst_port] = current_time

            syn_scans[source_ip] = {
                port: timestamp
                for port, timestamp in syn_scans[source_ip].items()
                if current_time - timestamp <= constants.TIMEFRAME
            }

            if len(syn_scans[source_ip]) > constants.SCAN_THRESHOLD:
                if source_ip not in ip_whitelist and src_port not in whitelisted_port and dst_port not in whitelisted_port:
                    write_to_log("SYN SCAN", packet, list(syn_scans[source_ip].keys()))


def xmas_scan(packet, ip_whitelist):
    if packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        source_ip = packet[IP].src
        if 'F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags and source_ip not in ip_whitelist:
            write_to_log("XMAS SCAN", packet, "TCP")


def null_scan(packet, ip_whitelist):
    if packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        source_ip = packet[IP].src
        if tcp_flags == 0 and source_ip not in ip_whitelist:
            write_to_log("NULL SCAN", packet, "TCP")


def type_scan(packet, ip_whitelist):
    tcp_connect_scan(packet, ip_whitelist)
    syn_scan(packet, ip_whitelist)
    xmas_scan(packet, ip_whitelist)
    null_scan(packet, ip_whitelist)


def dns_arp_spoof(packet, ip_whitelist):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if src_ip in arp_table and arp_table[src_ip] != src_mac:
            print(f"[ALERT] ARP Spoofing detected! IP: {src_ip}, MAC: {src_mac}")
            write_to_log("ARP SPOOFING", packet, src_mac)

    if packet.haslayer(DNS) and packet.haslayer(DNSRR):
        domain = packet[DNSRR].rrname.decode("utf-8")
        resolved_ip = packet[DNSRR].rdata
        current_time = time.time()

        if domain in dns_records:
            prev_ip, timestamp, change_count = dns_records[domain]

            # If the IP has changed and the time window is exceeded, check for spoofing
            if prev_ip != resolved_ip and (current_time - timestamp) <= constants.TIMEFRAME:
                # Consider allowing a certain number of changes before alerting
                if change_count < 10:
                    dns_records[domain] = (resolved_ip, current_time, change_count + 1)
                else:
                    print(f"[ALERT] DNS Spoofing Detected! {domain} changed from {prev_ip} to {resolved_ip} within {constants.TIMEFRAME} seconds")
                    write_to_log("DNS SPOOFING", packet, domain)

        # If it's the first time seeing this domain, add it to the records
        else:
            dns_records[domain] = (resolved_ip, current_time, 1)


def ssh_brute_force(packet, ip_whitelist):
    if packet.haslayer(TCP) and packet[TCP].dport == 22:
        src_ip = packet[IP].src

        if src_ip not in ip_whitelist:
            ssh_count[src_ip] = ssh_count.get(src_ip, 0) + 1

            if src_ip not in ssh_payloads:
                ssh_payloads[src_ip] = []

            if packet.haslayer(Raw):
                payload = packet[Raw].load
                ssh_payloads[src_ip].append(payload)

            if ssh_count[src_ip] > constants.SSH_THRESHOLD:
                write_to_log("SSH BRUTE FORCE", packet, ssh_payloads[src_ip])


def command_injection(packet, ip_whitelist):
    whitelisted_port = [80, 443]

    if packet.haslayer(Raw) and packet.haslayer(TCP) and packet[IP].src not in ip_whitelist and packet[TCP].dport not in whitelisted_port:
        payload = packet[Raw].load.decode(errors="ignore")

        patterns = [
            r"(cat\s+/etc/passwd)",
            r"(rm\s+-rf\s+/)",
            r"(cp\s+\S+\s+/tmp/|cp\s+/etc/\S+)",
            r"(mv\s+\S+\s+/tmp/|mv\s+/etc/\S+)",
            r"(chmod\s+[0-7]{3}\s+\S+)",
            r"(ifconfig\s+)",
            r"(iptables\s+)",
            r"(ps\s+aux)",
            r"(kill\s+\d+)",
            r"(top\s+-u\s+\S+)",
            r"(uname\s+-a)",
            r"(uptime\s+)",
            r"(echo\s+[^\n]*\s*\|\s*.*)",
            r"(echo\s+[^\n]*\s+>\s*\S+)",
            r"(sleep\s+\d+)",
        ]

        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                write_to_log("COMMAND INJECTION", packet, pattern)


def sql_injection(packet, ip_whitelist):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[IP].src not in ip_whitelist:
        payload = packet[Raw].load.decode(errors="ignore")
        patterns = [
            r"' OR '1'='1",
            r'UNION SELECT',
            r'; DROP TABLE',
            r'" OR "1"="1',
            r"' OR 1=1 --",
            r"admin' --",
        ]
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                write_to_log("SQL INJECTION", packet, pattern)


def type_other(packet, ip_whitelist):
    dns_arp_spoof(packet, ip_whitelist)
    ssh_brute_force(packet, ip_whitelist)
    command_injection(packet, ip_whitelist)
    sql_injection(packet, ip_whitelist)


# Runs Attack Analyzer to detect different attacks, to be called when sniffing network traffic
def attack_analyzer(packet):
    # ip_whitelist = ip_whitelisting(ip_address)
    
    ip_whitelist = set()
    ip_whitelist.add("192.168.1.66")

    type_flood(packet, ip_whitelist)
    type_scan(packet, ip_whitelist)
    type_other(packet, ip_whitelist)
    