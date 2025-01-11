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


def run_pcap_analyzer(filename): 
    syn_flood_pcap(filename, constants.TIMEFRAME, constants.THRESHOLD)
    udp_flood_pcap(filename, constants.TIMEFRAME, constants.THRESHOLD)
    icmp_flood_pcap(filename, constants.TIMEFRAME, constants.THRESHOLD)
    print("\n")