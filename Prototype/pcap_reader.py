import constants

import pyshark

from collections import defaultdict
from datetime import timedelta
import time
import re


def syn_flood_pcap(file_name, ip_whitelist):
    timeframe = constants.TIMEFRAME
    threshold = constants.FLOOD_THRESHOLD

    capture = pyshark.FileCapture(file_name, display_filter='tcp.flags.syn == 1 and tcp.flags.ack == 0')
    syn_count = defaultdict(list)

    for packet in capture:
        src_ip = packet.ip.src
        packet_time = packet.sniff_time
        syn_count[src_ip].append(packet_time)

    attacker_ip = []

    attacks = []
    attack_info = []

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

            if packet_count > threshold and src_ip not in attacker_ip and src_ip not in ip_whitelist:
                attacker_ip.append(src_ip)
                attack_info.append(timestamp)
                attack_info.append(src_ip)
                attack_info.append(packet.ip.dst)
                attack_info.append(packet[packet.transport_layer].srcport)
                attack_info.append(packet[packet.transport_layer].dstport)

                attacks.append(attack_info)

    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: SYN FLOOD")
            alert.append(f"Source IP and Port:{attack[1]}:{attack[3]}")
            alert.append(f"Destination IP and Port: {attack[2]}:{attack[4]}")

            alerts.append(alert)

        print(f"Potential SYN Flood Attacks detected from: {file_name}")

        return alerts
    else:
        alert.append("SYN Flood Attack Not Detected!")
        print(f"No SYN Flood detected from {file_name}")

        alerts.append(alert)
    
        return alerts


def udp_flood_pcap(file_name, ip_whitelist):
    timeframe = constants.TIMEFRAME
    threshold = constants.FLOOD_THRESHOLD

    capture = pyshark.FileCapture(file_name, display_filter='udp')
    udp_count = defaultdict(list)

    for packet in capture:
        src_ip = packet.ip.src
        packet_time = packet.sniff_time
        udp_count[src_ip].append(packet_time)

    attacker_ip = []

    attacks = []
    attack_info = []

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

            if packet_count > threshold and src_ip not in attacker_ip and src_ip not in ip_whitelist:
                attacker_ip.append(src_ip)
                attack_info.append(timestamp)
                attack_info.append(src_ip)
                attack_info.append(packet.ip.dst)
                attack_info.append(packet[packet.transport_layer].srcport)
                attack_info.append(packet[packet.transport_layer].dstport)

                attacks.append(attack_info)

    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: UDP FLOOD")
            alert.append(f"Source IP and Port:{attack[1]}:{attack[3]}")
            alert.append(f"Destination IP and Port: {attack[2]}:{attack[4]}")

            alerts.append(alert)

        print(f"Potential UDP Flood Attacks detected from: {file_name}")
        return alerts
    else:
        alert.append(f"UDP Flood Attack Not Detected!")
        print(f"No UDP Flood detected from {file_name}")

        alerts.append(alert)
    
        return alerts


def icmp_flood_pcap(file_name, ip_whitelist):
    timeframe = constants.TIMEFRAME
    threshold = constants.FLOOD_THRESHOLD

    capture = pyshark.FileCapture(file_name, display_filter='icmp.type == 8')
    icmp_count = defaultdict(list)

    for packet in capture:
        src_ip = packet.ip.src
        packet_time = packet.sniff_time
        icmp_count[src_ip].append(packet_time)

    attacker_ip = []

    attacks = []
    attack_info = []

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

            if packet_count > threshold and src_ip not in attacker_ip and src_ip not in ip_whitelist:
                attacker_ip.append(src_ip)
                attack_info.append(timestamp)
                attack_info.append(src_ip)
                attack_info.append(packet.ip.dst)

                attacks.append(attack_info)

    capture.close()
    
    alerts = []
    alert = []
    
    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: ICMP FLOOD")
            alert.append(f"Source IP:{attack[1]}")
            alert.append(f"Destination IP: {attack[2]}")

            alerts.append(alert)

        print(f"Potential UDP Flood Attacks detected from: {file_name}")
        return alerts
    else:
        alert.append(f"ICMP Flood Attack Not Detected!")
        print(f"No ICMP Flood detected from {file_name}")
    
        alerts.append(alert)

        return alerts


def tcp_connect_scan_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter="tcp")
    handshake_tracker = defaultdict(set)
    
    attacker_ip = []

    attacks = []
    attack_info = []

    for packet in capture:
        packet_time = packet.sniff_time
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
        if isinstance(ports, set) and len(ports) >= constants.SCAN_THRESHOLD and src_ip not in attacker_ip and src_ip not in ip_whitelist:
            attacker_ip.append(src_ip)

            attack_info.append(packet_time)
            attack_info.append(src_ip)
            attack_info.append(dst_ip)
            attack_info.append(src_port)
            attack_info.append(ports)

            attacks.append(attack_info)

    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: TCP CONNECT SCAN")
            alert.append(f"Source IP and port: {attack[1]}:{attack[3]}")
            alert.append(f"Destination IP: {attack[2]}")
            alert.append(f"List of scanned ports: {attack[4]}")

            alerts.append(alert)

        print(f"Potential TCP connect scan detected from: {file_name}")

        return alerts
    else:
        alert.append("TCP Connect Scan Not Detected!")
        print(f"No TCP connect scan detected from {file_name}")

        alerts.append(alert)

        return alerts


def syn_scan_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter="tcp.flags==0x02")
    syn_packets = {}

    attacker_ip = []

    attacks = []
    attack_info = []

    for packet in capture:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
        timestamp = float(packet.sniff_timestamp)
        syn_packets.setdefault(src_ip, {}).update({dst_port: timestamp})

    for src_ip, ports in syn_packets.items():
        if len(ports) > constants.SCAN_THRESHOLD and src_ip not in attacker_ip and src_ip not in ip_whitelist:
            attacker_ip.append(src_ip)

            attack_info.append(packet.sniff_time)
            attack_info.append(src_ip)
            attack_info.append(dst_ip)
            attack_info.append(src_port)
            attack_info.append(ports)

            attacks.append(attack_info)

    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: SYN SCAN")
            alert.append(f"Source IP and port: {attack[1]}:{attack[3]}")
            alert.append(f"Destination IP: {attack[2]}")
            alert.append(f"List of scanned ports: {attack[4]}")

            alerts.append(alert)

        print(f"Potential SYN scan detected from: {file_name}")

        return alerts
    else:
        alert.append("SYN Scan Not Detected!")
        print(f"No SYN scan detected from {file_name}")

        alerts.append(alert)

        return alerts


def xmas_scan_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter="tcp.flags==0x29")

    attacker_ip = []

    attacks = []
    attack_info = []

    for packet in capture:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)

        if src_ip not in ip_whitelist:
            # attacker_ip.append(src_ip)

            attack_info.append(packet.sniff_time)
            attack_info.append(src_ip)
            attack_info.append(dst_ip)
            attack_info.append(src_port)
            attack_info.append(dst_port)

            attacks.append(attack_info)
        
    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: XMAS SCAN")
            alert.append(f"Source IP and port: {attack[1]}:{attack[3]}")
            alert.append(f"Destination IP and port: {attack[2]}:{attack[4]}")

            alerts.append(alert)

        print(f"Potential Xmas scan detected from: {file_name}")
        return alerts
    else:
        alert.append("No XMas Scan Detected!")
        print(f"No Xmas scan detected from {file_name}")

        alerts.append(alert)

        return alerts
    

def null_scan_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name, display_filter="tcp.flags==0x00")

    attacker_ip = []

    attacks = []
    attack_info = []

    for packet in capture:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)

        if src_ip not in ip_whitelist:
            # attacker_ip.append(src_ip)
            
            attack_info.append(packet.sniff_time)
            attack_info.append(src_ip)
            attack_info.append(dst_ip)
            attack_info.append(src_port)
            attack_info.append(dst_port)

            attacks.append(attack_info)

    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: NULL SCAN")
            alert.append(f"Source IP and port: {attack[1]}:{attack[3]}")
            alert.append(f"Destination IP and port: {attack[2]}:{attack[4]}")

            alerts.append(alert)

        print(f"Potential Null scan detected from: {file_name}")
        return alerts
    else:
        alert.append("Null Scan Not Detected!")
        print(f"No Null scan detected from {file_name}")
        
        alerts.append(alert)

        return alerts


def dns_arp_spoof_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name)

    dns_records = {}
    arp_table = {}

    attacker_ip = []
    
    attacks = []
    attack_info = []

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
                            # print(f"[ALERT] DNS Spoofing Detected! {domain} changed from {prev_ip} to {resolved_ip} within {constants.TIMEFRAME} seconds")
                            
                            attacker_ip.append(packet.ip.src)

                            attack_info.append(packet.sniff_time)
                            attack_info.append(prev_ip)
                            attack_info.append(resolved_ip)
                            attack_info.append(domain)

                            attacks.append(attack_info)
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
                    attacker_ip.append(src_ip)
                    
                    attack_info.append(packet.sniff_time)
                    attack_info.append(src_ip)
                    attack_info.append(src_mac)

                    attacks.append(attack_info)
            except AttributeError:
                pass  

    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: DNS / ARP SPOOFING")
            alert.append(f"{attack[1]} -> {attack[2]}")
            try:
                alert.append(f"Domain: {attack[3]}")
            except IndexError:
                pass
            
            alerts.append(alert)

        print(f"Potential DNS/ARP Spoofing detected from: {file_name}")
        return alerts
    else:
        alert.append("No DNS/ARP Spoofing Detected!")

        print(f"No DNS/ARP Spoofing detected from {file_name}")

        alerts.append(alert)
        return alerts


def ssh_brute_force_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name)

    ssh_count = {}

    attacker_ip = []

    attacks = []
    attack_info = []
    
    for packet in capture:
         if 'TCP' in packet and hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dport'):
            try:
                if int(packet.tcp.dport) == 22:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst

                    if src_ip not in ip_whitelist and src_ip not in attacker_ip:
                        ssh_count[src_ip] = ssh_count.get(src_ip, 0) + 1
                        if ssh_count[src_ip] > constants.SSH_THRESHOLD:
                            print(f"[ALERT] SSH Brute Force detected from {src_ip}")
                            attacker_ip.append(src_ip)
                            
                            attack_info.append(packet.sniff_time)
                            attack_info.append(src_ip)
                            attack_info.append(dst_ip)

                            attacks.append(attack_info)

            except AttributeError:
                pass

    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: SSH BRUTE FORCE")
            alert.append(f"Source IP: {attack[1]}")
            alert.append(f"Destination IP: {attack[2]}")

            alerts.append(alert)

        print(f"Potential SSH Brute Force attack detected from: {file_name}")
        return alerts
    else:
        alert.append("No SSH Brute Force Detected!")
        print(f"No SSH Brute Force detected from {file_name}")

        alerts.append(alert)

        return alerts


def command_injection_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name)

    attacker_ip = []
    
    attacks = []
    attack_info = []

    whitelisted_ports = [80, 443]

    for packet in capture:
        if 'TCP' in packet and 'Raw' in packet and int(packet.ip.src) not in ip_whitelist:
            if int(packet.tcp.dport) not in whitelisted_ports:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
                
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
                        attacker_ip.append(src_ip)

                        attack_info.append(packet.sniff_time)
                        attack_info.append(src_ip)
                        attack_info.append(dst_ip)
                        attack_info.append(src_port)
                        attack_info.append(dst_port)
                        attack_info.append(pattern)

                        attacks.append(attack_info)

    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: COMMAND INJECTION")
            alert.append(f"Source IP and port: {attack[1]}:{attack[3]}")
            alert.append(f"Destination IP and port: {attack[2]}:{attack[4]}")
            alert.append(f"Command: {pattern}")

            alerts.append(alert)

        print(f"Potential Command Injection detected from: {file_name}")
        return alerts
    else:
        alert.append("No Command Injection Detected!")
        print(f"No Command Injection detected from {file_name}")

        alerts.append(alert)

        return alerts


def sql_injection_pcap(file_name, ip_whitelist):
    capture = pyshark.FileCapture(file_name)

    attacker_ip = []

    attacks = []
    attack_info = []

    for packet in capture:
        if 'TCP' in packet and 'Raw' in packet and int(packet.ip.src) not in ip_whitelist:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)

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
                    attacker_ip.append(src_ip)

                    attack_info.append(packet.sniff_time)
                    attack_info.append(src_ip)
                    attack_info.append(dst_ip)
                    attack_info.append(src_port)
                    attack_info.append(dst_port)
                    attack_info.append(pattern)

                    attacks.append(attack_info)

    capture.close()

    alerts = []
    alert = []

    if len(attacks) > 0:
        for attack in attacks:
            alert.append(attack[0])
            alert.append("Attack Type: SQL INJECTION")
            alert.append(f"Source IP and port: {attack[1]}:{attack[3]}")
            alert.append(f"Destination IP and port: {attack[2]}:{attack[4]}")
            alert.append(f"Command: {pattern}")

            alerts.append(alert)

        print(f"Potential SQL Injection detected from: {file_name}")
        return alerts
    else:
        alert.append("No SQL Injection Detected!")
        print(f"No SQL Injection detected from {file_name}")

        alerts.append(alert)

        return alerts


def run_pcap_analyzer(file_name, ip_whitelist):
    alerts = syn_flood_pcap(file_name, ip_whitelist)
    alerts += udp_flood_pcap(file_name, ip_whitelist)
    alerts += icmp_flood_pcap(file_name, ip_whitelist)
    print("")

    alerts += tcp_connect_scan_pcap(file_name, ip_whitelist)
    alerts += syn_scan_pcap(file_name, ip_whitelist)
    alerts += xmas_scan_pcap(file_name, ip_whitelist)
    alerts += null_scan_pcap(file_name, ip_whitelist)
    print("")

    alerts += dns_arp_spoof_pcap(file_name, ip_whitelist)
    alerts += ssh_brute_force_pcap(file_name, ip_whitelist)
    alerts += command_injection_pcap(file_name, ip_whitelist)
    alerts += sql_injection_pcap(file_name, ip_whitelist)
    print("")

    print("=================")
    print("ANALYSIS COMPLETE")
    print("=================")

    return alerts
