import constants

from scapy.layers.inet import IP
import pyshark

from collections import defaultdict
from datetime import timedelta
import time
import re


ip_whitelist = set()

def ip_whitelisting(ip_address):
    if ip_address is not None and ip_address not in ip_whitelist:
        ip_whitelist.add(ip_address)
        print(f"IP: {ip_address} added to the whitelist")

    return ip_whitelist


def syn_flood_pcap(file_name, timeframe, threshold, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter='tcp.flags.syn == 1 and tcp.flags.ack == 0')
    syn_count = defaultdict(list)

    for packet in capture:
        src_ip = packet.ip.src
        packet_time = packet.sniff_time
        syn_count[src_ip].append(packet_time)

    attacker_ip = set()

    for src_ip, timestamps in syn_count.items():
        timestamps.sort()

        start_time = timestamps[0]
        packet_count = 0

        for timestamp in timestamps:
            if timestamp - start_time <= timedelta(seconds=timeframe):
                packet_count += 1
            else:
                start_time = timestamp
                packet_count = 1

            if packet_count > threshold and src_ip not in ip_whitelist:
                attacker_ip.add(src_ip)

    if attacker_ip:
        print(f"Potential SYN Flood Attacks detected from: {attacker_ip}")
    else:
        print(f"No SYN Flood detected from {file_name}")

    capture.close()


def udp_flood_pcap(file_name, timeframe, threshold, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter='udp')
    udp_count = defaultdict(list)

    for packet in capture:
        src_ip = packet.ip.src
        packet_time = packet.sniff_time
        udp_count[src_ip].append(packet_time)

    attacker_ip = set()

    for src_ip, timestamps in udp_count.items():
        timestamps.sort()

        start_time = timestamps[0]
        packet_count = 0

        for timestamp in timestamps:
            if timestamp - start_time <= timedelta(seconds=timeframe):
                packet_count += 1
            else:
                start_time = timestamp
                packet_count = 1

            if packet_count > threshold and src_ip not in ip_whitelist:
                attacker_ip.add(src_ip)

    if attacker_ip:
        print(f"Potential UDP Flood Attacks detected from: {attacker_ip}")
    else:
        print(f"No UDP Flood detected from {file_name}")

    capture.close()


def icmp_flood_pcap(file_name, timeframe, threshold, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter='icmp.type == 8')
    icmp_count = defaultdict(list)

    for packet in capture:
        src_ip = packet.ip.src
        packet_time = packet.sniff_time
        icmp_count[src_ip].append(packet_time)

    attacker_ip = set()

    for src_ip, timestamps in icmp_count.items():
        timestamps.sort()

        start_time = timestamps[0]
        packet_count = 0

        for timestamp in timestamps:
            if timestamp - start_time <= timedelta(seconds=timeframe):
                packet_count += 1
            else:
                start_time = timestamp
                packet_count = 1

            if packet_count > threshold and src_ip not in ip_whitelist:
                attacker_ip.add(src_ip)

    if attacker_ip:
        print(f"Potential ICMP Flood Attacks detected from: {attacker_ip}")
    else:
        print(f"No ICMP Flood detected from {file_name}")

    capture.close()


def tcp_connect_scan_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter="tcp")
    handshake_tracker = defaultdict(set)
    
    attacker_ip = set()

    for packet in capture:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
        flags = int(packet.tcp.flags, 16)

        if flags == 0x02:  # SYN
            handshake_tracker[(src_ip, dst_port)] = 'SYN'
        elif flags == 0x12:  # SYN-ACK
            if handshake_tracker.get((dst_ip, src_port)) == 'SYN':
                handshake_tracker[(dst_ip, src_port)] = 'SYN-ACK'
        elif flags == 0x10:  # ACK
            if handshake_tracker.get((src_ip, dst_port)) == 'SYN-ACK':
                handshake_tracker[src_ip].add(dst_port)

    for src_ip, ports in handshake_tracker.items():
        if isinstance(ports, set) and len(ports) >= constants.SCAN_THRESHOLD and src_ip not in ip_whitelist:
            print(f"TCP Connect Scan detected from {src_ip}: Scanned ports: {sorted(ports)}")
            attacker_ip.add(src_ip)

    if attacker_ip:
        print(f"Potential TCP connect scan detected from: {attacker_ip}")
    else:
        print(f"No TCP connect scan detected from {file_name}")

    capture.close()


def syn_scan_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter="tcp.flags==0x02")
    syn_packets = {}

    attacker_ip = set()

    for packet in capture:
        src_ip = packet.ip.src
        dst_port = int(packet.tcp.dstport)
        timestamp = float(packet.sniff_timestamp)
        syn_packets.setdefault(src_ip, {}).update({dst_port: timestamp})

    for src_ip, ports in syn_packets.items():
        if len(ports) > constants.SCAN_THRESHOLD and src_ip not in ip_whitelist:
            print(f"SYN Scan detected from {src_ip}: Scanned ports: {list(ports.keys())}")
            attacker_ip.add(src_ip)

    if attacker_ip:
        print(f"Potential SYN scan detected from: {attacker_ip}")
    else:
        print(f"No SYN scan detected from {file_name}")

    capture.close()


def xmas_scan_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter="tcp.flags==0x29")

    attacker_ip = set()

    for packet in capture:
        src_ip = packet.ip.src

        if src_ip not in ip_whitelist:
            print(f"Xmas Scan detected: Abnormal packet from {src_ip}")
            attacker_ip.add(src_ip)
        

    if attacker_ip:
        print(f"Potential Xmas scan detected from: {attacker_ip}")
    else:
        print(f"No Xmas scan detected from {file_name}")

    capture.close()


def null_scan_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter="tcp.flags==0x00")

    attacker_ip = set()

    for packet in capture:
        src_ip = packet.ip.src

        if src_ip not in ip_whitelist:
            print(f"Null Scan detected: Abnormal packet from {src_ip}")
            attacker_ip.add(src_ip)

    if attacker_ip:
        print(f"Potential Null scan detected from: {attacker_ip}")
    else:
        print(f"No Null scan detected from {file_name}")

    capture.close()


def dns_arp_spoof_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name)

    attacker_ip = set()
    dns_records = {}
    arp_table = {}

    for packet in capture:
        if 'DNS' in packet:
            try:
                domain = packet.dns.qry_name
                resolved_ip = packet.dns.a
                current_time = time.time()

                if domain in dns_records:
                    prev_ip, timestamp, change_count = dns_records[domain]

                    if prev_ip != resolved_ip and (current_time - timestamp) <= constants.TIMEFRAME:
                        if change_count < 10:
                            dns_records[domain] = (resolved_ip, current_time, change_count + 1)
                        else:
                            print(f"[ALERT] DNS Spoofing Detected! {domain} changed from {prev_ip} to {resolved_ip} within {constants.TIMEFRAME} seconds")
                            attacker_ip.add(packet.ip.src)
                else:
                    dns_records[domain] = (resolved_ip, current_time, 1)
            except AttributeError:
                pass

        if 'ARP' in packet:
            try:
                src_ip = packet.arp.psrc
                src_mac = packet.arp.hwsrc
                if src_ip in arp_table and arp_table[src_ip] != src_mac:
                    print(f"[ALERT] ARP Spoofing detected! IP: {src_ip}, MAC: {src_mac}")
                    attacker_ip.add(src_ip)
            except AttributeError:
                pass  

    if attacker_ip:
        print(f"Potential DNS/ARP Spoofing detected from: {attacker_ip}")
    else:
        print(f"No DNS/ARP Spoofing detected from {file_name}")

    capture.close()


def ssh_brute_force_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name)

    attacker_ip = set()
    ssh_count = {}

    for packet in capture:
         if 'TCP' in packet and hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dport'):
            try:
                if int(packet.tcp.dport) == 22:
                    src_ip = packet.ip.src

                    if src_ip not in ip_whitelist:
                        ssh_count[src_ip] = ssh_count.get(src_ip, 0) + 1
                        if ssh_count[src_ip] > constants.SSH_THRESHOLD:
                            print(f"[ALERT] SSH Brute Force detected from {src_ip}")
                            attacker_ip.add(src_ip)

            except AttributeError:
                pass

    if attacker_ip:
        print(f"Potential SSH Brute Force attack detected from: {attacker_ip}")
    else:
        print(f"No SSH Brute Force detected from {file_name}")

    capture.close()


def command_injection_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name)

    attacker_ip = set()

    whitelisted_ports = [80, 443]

    for packet in capture:
        if 'TCP' in packet and 'Raw' in packet and int(packet.ip.src) not in ip_whitelist:
            if int(packet.tcp.dport) not in whitelisted_ports:
                payload = packet['Raw'].load.decode(errors="ignore")

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
                    r"(echo\s+\S+)",
                    r"(sleep\s+\d+)",
                ]

                for pattern in patterns:
                    if re.search(pattern, payload, re.IGNORECASE):
                        print(f"[ALERT] Command Injection Detected in live traffic: {pattern}")
                        attacker_ip.add(packet.ip.src)

    if attacker_ip:
        print(f"Potential Command Injection detected from: {attacker_ip}")
    else:
        print(f"No Command Injection detected from {file_name}")

    capture.close()


def sql_injection_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name)

    attacker_ip = set()

    for packet in capture:
        if 'TCP' in packet and 'Raw' in packet and int(packet.ip.src) not in ip_whitelist:
            payload = packet['Raw'].load.decode(errors="ignore")
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
                    print(f"[ALERT] SQL Injection Detected in live traffic: {pattern}")
                    attacker_ip.add(packet.ip.src)

    if attacker_ip:
        print(f"Potential SQL Injection detected from: {attacker_ip}")
    else:
        print(f"No SQL Injection detected from {file_name}")

    capture.close()


def run_pcap_analyzer(file_name):
    ip_whitelist = set()

    # ip_whitelist = ip_whitelisting(ip_address)
    
    syn_flood_pcap(file_name, constants.TIMEFRAME, constants.FLOOD_THRESHOLD, ip_whitelist)
    udp_flood_pcap(file_name, constants.TIMEFRAME, constants.FLOOD_THRESHOLD, ip_whitelist)
    icmp_flood_pcap(file_name, constants.TIMEFRAME, constants.FLOOD_THRESHOLD, ip_whitelist)
    print("")

    tcp_connect_scan_pcap(file_name, ip_whitelist)
    syn_scan_pcap(file_name, ip_whitelist)
    xmas_scan_pcap(file_name, ip_whitelist)
    null_scan_pcap(file_name, ip_whitelist)
    print("")

    dns_arp_spoof_pcap(file_name, ip_whitelist)
    ssh_brute_force_pcap(file_name, ip_whitelist)
    command_injection_pcap(file_name, ip_whitelist)
    sql_injection_pcap(file_name, ip_whitelist)
    print("")

    print("=================")
    print("ANALYSIS COMPLETE")
    print("=================")
