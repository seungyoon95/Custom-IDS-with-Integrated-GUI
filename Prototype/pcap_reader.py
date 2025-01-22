import constants
import pyshark
from collections import defaultdict
from datetime import timedelta


def syn_flood_pcap(file_name, timeframe, threshold):
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

            if packet_count > threshold:
                attacker_ip.add(src_ip)

    if attacker_ip:
        print(f"Potential SYN Flood Attacks detected from: {attacker_ip}")
    else:
        print(f"No SYN Flood detected from {file_name}")

    capture.close()


def udp_flood_pcap(file_name, timeframe, threshold):
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

            if packet_count > threshold:
                attacker_ip.add(src_ip)

    if attacker_ip:
        print(f"Potential UDP Flood Attacks detected from: {attacker_ip}")
    else:
        print(f"No UDP Flood detected from {file_name}")

    capture.close()


def icmp_flood_pcap(file_name, timeframe, threshold):
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

            if packet_count > threshold:
                attacker_ip.add(src_ip)

    if attacker_ip:
        print(f"Potential ICMP Flood Attacks detected from: {attacker_ip}")
    else:
        print(f"No ICMP Flood detected from {file_name}")

    capture.close()


def ping_of_death_pcap(file_name):
    capture = pyshark.FileCapture(file_name)

    attacker_ip = set()

    for packet in capture:
        if hasattr(packet, 'ip'):
            ip_layer = packet.ip
            size = int(ip_layer.len)

            if size > 65535:
                attacker_ip.add(ip_layer.src)
                print(f"Potential Ping of Death detected from: {ip_layer.src}")

    if attacker_ip:
        print(f"Potential Ping of Death detected from: {attacker_ip}")
    else:
        print(f"No Ping of Death detected from {file_name}")


def flood_pcap(file_name):
    syn_flood_pcap(file_name, constants.TIMEFRAME, constants.FLOOD_THRESHOLD)
    udp_flood_pcap(file_name, constants.TIMEFRAME, constants.FLOOD_THRESHOLD)
    icmp_flood_pcap(file_name, constants.TIMEFRAME, constants.FLOOD_THRESHOLD)
    ping_of_death_pcap(file_name)
    print("\n")


def tcp_connect_scan_pcap(file_name):
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
        if isinstance(ports, set) and len(ports) >= constants.SCAN_THRESHOLD:
            print(f"TCP Connect Scan detected from {src_ip}: Scanned ports: {sorted(ports)}")

    if attacker_ip:
        print(f"Potential TCP connect scan detected from: {attacker_ip}")
    else:
        print(f"No TCP connect scan detected from {file_name}")


def syn_scan_pcap(file_name):
    capture = pyshark.FileCapture(file_name, display_filter="tcp.flags==0x02")
    syn_packets = {}

    attacker_ip = set()

    for packet in capture:
        src_ip = packet.ip.src
        dst_port = int(packet.tcp.dstport)
        timestamp = float(packet.sniff_timestamp)
        syn_packets.setdefault(src_ip, {}).update({dst_port: timestamp})

    for src_ip, ports in syn_packets.items():
        if len(ports) > constants.SCAN_THRESHOLD:
            print(f"SYN Scan detected from {src_ip}: Scanned ports: {list(ports.keys())}")

    if attacker_ip:
        print(f"Potential SYN scan detected from: {attacker_ip}")
    else:
        print(f"No SYN scan detected from {file_name}")


def xmas_scan_pcap(file_name):
    capture = pyshark.FileCapture(file_name, display_filter="tcp.flags==0x29")

    attacker_ip = set()

    for packet in capture:
        src_ip = packet.ip.src
        print(f"Xmas Scan detected: Abnormal packet from {src_ip}")

    if attacker_ip:
        print(f"Potential Xmas scan detected from: {attacker_ip}")
    else:
        print(f"No Xmas scan detected from {file_name}")


def null_scan_pcap(file_name):
    capture = pyshark.FileCapture(file_name, display_filter="tcp.flags==0x00")

    attacker_ip = set()

    for packet in capture:
        src_ip = packet.ip.src
        print(f"Null Scan detected: Abnormal packet from {src_ip}")

    if attacker_ip:
        print(f"Potential Null scan detected from: {attacker_ip}")
    else:
        print(f"No Null scan detected from {file_name}")


def scan_pcap(file_name):
    tcp_connect_scan_pcap(file_name)
    syn_scan_pcap(file_name)
    xmas_scan_pcap(file_name)
    null_scan_pcap(file_name)
    print("\n")


def run_pcap_analyzer(file_name): 
    flood_pcap(file_name)
    scan_pcap(file_name)