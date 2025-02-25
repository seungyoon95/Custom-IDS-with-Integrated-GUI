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

pending_handshake = defaultdict(deque)

completed_handshake = {}
syn_scans = {}

arp_cache = {}
dns_cache = {}

dns_records = {}
ssh_count = {}
ssh_payloads = {}

ip_whitelist = set()

# Host IP address
local_ip = socket.gethostbyname(socket.gethostname())

shared_alert = []

def display_on_gui(attack_type, packet, info=None):
    print("\n===========================================")
    print(datetime.now())
    print(f"Attack Type: {attack_type}")

    shared_alert.append(datetime.now())
    shared_alert.append(f"Attack Type: {attack_type}")

    if info == "TCP" and type(info) != set:
        print(f"Source IP and Port: {packet[IP].src}:{packet[TCP].sport}")
        print(f"Destination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")

        shared_alert.append(f"Source IP and Port: {packet[IP].src}:{packet[TCP].sport}")
        shared_alert.append(f"Destination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")

    if info == "UDP":
        print(f"Source IP and Port: {packet[IP].src}:{packet[UDP].sport}")
        print(f"Destination IP and Port: {packet[IP].dst}:{packet[UDP].dport}")

        shared_alert.append(f"Source IP and Port: {packet[IP].src}:{packet[UDP].sport}")
        shared_alert.append(f"Destination IP and Port: {packet[IP].dst}:{packet[UDP].dport}")

    if info == "ICMP":
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")

        shared_alert.append(f"Source IP: {packet[IP].src}")
        shared_alert.append(f"Destination IP: {packet[IP].dst}")

    if (attack_type == "SYN SCAN" or attack_type == "TCP CONNECT SCAN") and type(info) == list:
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"List of scanned ports: {info}")

        shared_alert.append(f"Source IP: {packet[IP].src}")
        shared_alert.append(f"Destination IP: {packet[IP].dst}")
        shared_alert.append(f"List of scanned ports: {info}")
    
    if attack_type == "ARP SPOOFING":
        print(f"Source Mac Address: {info}")

        shared_alert.append(f"Source Mac Address: {info}")
    
    if attack_type == "DNS SPOOFING":
        print(f"Affected Domain: {info}")

        shared_alert.append(f"Affected Domain: {info}")
    
    if attack_type == "SSH BRUTE FORCE":
        payload = []
        print(f"Source IP and Port: {packet[IP].src}:{packet[TCP].sport}")
        print(f"Destination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
        for p in info:
            print(p)
            payload.insert(p)

        shared_alert.append(f"Source IP and Port: {packet[IP].src}:{packet[TCP].sport}")
        shared_alert.append(f"Destination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
        shared_alert.append(payload)
    
    if attack_type == "COMMAND INJECTION":
        print(f"Source IP and Port: {packet[IP].src}:{packet[TCP].sport}")
        print(f"Destination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
        print(f"Command Detected: {info}")

        shared_alert.append(f"Source IP and Port: {packet[IP].src}:{packet[TCP].sport}")
        shared_alert.append(f"Destination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
        shared_alert.append(f"Command Detected: {info}")

    if attack_type == "SQL INJECTION":
        print(f"Source IP and Port: {packet[IP].src}:{packet[TCP].sport}")
        print(f"Destination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
        print(f"Command Detected: {info}")

        shared_alert.append(f"Source IP and Port: {packet[IP].src}:{packet[TCP].sport}")
        shared_alert.append(f"Destination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
        shared_alert.append(f"Command Detected: {info}")

# Writes packet info to a log file
def write_to_log(attack_type, packet, info=None):
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
        
        if attack_type == "ARP SPOOFING":
            f.write(f"\nSpoofed Mac Address: {info}")
        if attack_type == "DNS SPOOFING":
            f.write(f"\nSource IP: {packet[IP].src}")
            f.write(f"\nDestination IP: {packet[IP].dst}")
            f.write(f"\nAffected Domain: {info}")
        if attack_type == "SSH BRUTE FORCE":
            f.write(f"\nSource IP and Port: {packet[IP].src}:{packet[TCP].sport}")
            f.write(f"\nDestination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
            for payload in info:
                f.write(f"\n{payload}")
        if attack_type == "COMMAND INJECTION":
            f.write(f"\nSource IP and Port: {packet[IP].src}:{packet[TCP].sport}")
            f.write(f"\nDestination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
            f.write(f"\nCommand Detected: {info}")
        if attack_type == "SQL INJECTION":
            f.write(f"\nSource IP and Port: {packet[IP].src}:{packet[TCP].sport}")
            f.write(f"\nDestination IP and Port: {packet[IP].dst}:{packet[TCP].dport}")
            f.write(f"\nCommand Detected: {info}")
    

def alert_to_email(attack_type, packet, info=None):
    pass

def ip_whitelisting(ip_address):
    for ip in ip_address:
        if ip is not None and ip not in ip_whitelist:
            ip_whitelist.add(ip)
            print(f"IP: {ip} added to the whitelist")

    return ip_whitelist


# Detects SYN Flood Attack based on given timeframe and threshold
def syn_flood(packet, ip_whitelist, log, gui_display, email):
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
                        syn_flood_alerted.add(source_ip)
                        if log:
                            write_to_log("SYN FLOOD", packet, "TCP")
                        if gui_display:
                            display_on_gui("SYN FLOOD", packet, "TCP")
                        if email:
                            alert_to_email("SYN FLOOD", packet, "TCP")

            elif packet[TCP].flags == 'A':
                if (source_ip, dst_ip) in pending_handshake:
                    if pending_handshake[(source_ip, dst_ip)]:
                        pending_handshake[(source_ip, dst_ip)].popleft()    
                

# Detects UDP Flood Attack based on given timeframe and threshold
def udp_flood(packet, ip_whitelist, log, gui_display, email):
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
                    udp_flood_alerted.add(source_ip)
                    if log:
                        write_to_log("UDP FLOOD", packet, "UDP")
                    if gui_display:
                        display_on_gui("UDP FLOOD", packet, "UDP")
                    if email:
                        alert_to_email("UDP FLOOD", packet, "UDP")


# Detects ICMP Flood Attack based on given timeframe and threshold
def icmp_flood(packet, ip_whitelist, log, gui_display, email):
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        source_ip = packet[IP].src
        current_time = time.time()

        if source_ip not in ip_whitelist:
            icmp_count[source_ip].append(current_time)
            icmp_count[source_ip] = [t for t in icmp_count[source_ip] if current_time - t < constants.TIMEFRAME]

            if len(icmp_count[source_ip]) > constants.FLOOD_THRESHOLD:
                if source_ip != local_ip and source_ip not in ip_whitelist and source_ip not in icmp_flood_alerted:
                    icmp_flood_alerted.add(source_ip)
                    if log:
                        write_to_log("ICMP FLOOD", packet, "ICMP")
                    if gui_display:
                        display_on_gui("ICMP FLOOD", packet, "ICMP")
                    if email:
                        alert_to_email("ICMP FLOOD", packet, "ICMP")


def type_flood(packet, ip_whitelist, log, gui_display, email):
    syn_flood(packet, ip_whitelist, log, gui_display, email)
    udp_flood(packet, ip_whitelist, log, gui_display, email)
    icmp_flood(packet, ip_whitelist, log, gui_display, email)


def tcp_connect_scan(packet, ip_whitelist, log, gui_display, email):
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
                if source_ip not in ip_whitelist and src_port not in whitelisted_port and dst_port not in whitelisted_port:
                    if log:
                        write_to_log("TCP CONNECT SCAN", packet, list(completed_handshake[source_ip].keys()))
                    if gui_display:
                        display_on_gui("TCP CONNECT SCAN", packet, list(completed_handshake[source_ip].keys()))
                    if email:
                        alert_to_email("TCP CONNECT SCAN", packet, list(completed_handshake[source_ip].keys()))



def syn_scan(packet, ip_whitelist, log, gui_display, email):
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
                    if log:
                        write_to_log("SYN SCAN", packet, list(syn_scans[source_ip].keys()))
                    if gui_display:
                        display_on_gui("SYN SCAN", packet, list(syn_scans[source_ip].keys()))
                    if email:
                        alert_to_email("SYN SCAN", packet, list(syn_scans[source_ip].keys()))


def xmas_scan(packet, ip_whitelist, log, gui_display, email):
    if packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        source_ip = packet[IP].src
        if 'F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags and source_ip not in ip_whitelist:
            if log:
                write_to_log("XMAS SCAN", packet, "TCP")
            if gui_display:
                display_on_gui("XMAS SCAN", packet, "TCP")
            if email:
                alert_to_email("XMAS SCAN", packet, "TCP")


def null_scan(packet, ip_whitelist, log, gui_display, email):
    if packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        source_ip = packet[IP].src
        if tcp_flags == 0 and source_ip not in ip_whitelist:
            if log:
                write_to_log("NULL SCAN", packet, "TCP")
            if gui_display:
                display_on_gui("NULL SCAN", packet, "TCP")
            if email:
                alert_to_email("NULL SCAN", packet, "TCP")            


def type_scan(packet, ip_whitelist, log, gui_display, email):
    tcp_connect_scan(packet, ip_whitelist, log, gui_display, email)
    syn_scan(packet, ip_whitelist, log, gui_display, email)
    xmas_scan(packet, ip_whitelist, log, gui_display, email)
    null_scan(packet, ip_whitelist, log, gui_display, email)


def dns_arp_spoof(packet, ip_whitelist, log, gui_display, email):
    arp_cache["192.168.1.1"] = "a8-fb-40-9d-d1-03" # for testing
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if src_ip in arp_cache:
            if arp_cache[src_ip] != src_mac:
                if log:
                    write_to_log("ARP SPOOFING", packet, src_mac)
                if gui_display:
                    display_on_gui("ARP SPOOFING", packet, src_mac)
                if email:
                    alert_to_email("ARP SPOOFING", packet, src_mac)
                
            else:
                arp_cache[src_ip] = src_mac

    # if packet.haslayer(DNS) and packet.haslayer(DNSRR):
    #     print(packet.summary())
    #     domain = packet[DNSRR].rrname.decode("utf-8")
    #     resolved_ip = packet[DNSRR].rdata
    #     current_time = time.time()

    #     if domain in dns_records:
    #         prev_ip, timestamp, change_count = dns_records[domain]

    #         if prev_ip != resolved_ip and (current_time - timestamp) <= constants.TIMEFRAME:
    #             if change_count < 10:
    #                 dns_records[domain] = (resolved_ip, current_time, change_count + 1)
    #             else:
    #                 if log:
    #                     write_to_log("DNS SPOOFING", packet, domain)
    #                 if gui_display:
    #                     display_on_gui("DNS SPOOFING", packet, src_mac)
    #                 if email:
    #                     alert_to_email("DNS SPOOFING", packet, src_mac)
    #     else:
    #         dns_records[domain] = (resolved_ip, current_time, 1)


def ssh_brute_force(packet, ip_whitelist, log, gui_display, email):
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
                if log:
                    write_to_log("SSH BRUTE FORCE", packet, ssh_payloads[src_ip])
                if gui_display:
                    display_on_gui("SSH BRUTE FORCE", packet, ssh_payloads[src_ip])
                if email:
                    alert_to_email("SSH BRUTE FORCE", packet, ssh_payloads[src_ip])


def command_injection(packet, ip_whitelist, log, gui_display, email):
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
                if log:
                    write_to_log("COMMAND INJECTION", packet, pattern)
                if gui_display:
                    display_on_gui("COMMAND INJECTION", packet, pattern)
                if email:
                    alert_to_email("COMMAND INJECTION", packet, pattern)


def sql_injection(packet, ip_whitelist, log, gui_display, email):
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
                if log:
                    write_to_log("SQL INJECTION", packet, pattern)
                if gui_display:
                    display_on_gui("SQL INJECTION", packet, pattern)
                if email:
                    alert_to_email("SQL INJECTION", packet, pattern)


def type_other(packet, ip_whitelist, log, gui_display, email):
    dns_arp_spoof(packet, ip_whitelist, log, gui_display, email)
    ssh_brute_force(packet, ip_whitelist, log, gui_display, email)
    command_injection(packet, ip_whitelist, log, gui_display, email)
    sql_injection(packet, ip_whitelist, log, gui_display, email)


# Runs Attack Analyzer to detect different attacks, to be called when sniffing network traffic
def attack_analyzer(packet, ip_address=None, log=True, gui_display=False, email=False):
    ip_whitelist = ip_whitelisting(ip_address)
        
    type_flood(packet, ip_whitelist, log, gui_display, email)
    type_scan(packet, ip_whitelist, log, gui_display, email)
    type_other(packet, ip_whitelist, log, gui_display, email)
    