import constants


from datetime import datetime
import time
import os
import socket
from collections import defaultdict, deque


# Dictionaries to hold packet counts from 
syn_count = defaultdict(list)
udp_count = defaultdict(list)
icmp_count = defaultdict(list)

pending_handshake = defaultdict(deque)

completed_handshake = defaultdict(dict)
syn_scans = {}

ip_whitelist = set()

# Host IP address
local_ip = socket.gethostbyname(socket.gethostname())


# Writes packet info to a log file
def write_to_log(packet):
    current_date = datetime.now().strftime('%Y-%m-%d')

    # Creating log directory if it doesn't already exist
    log_directory = './logs'
    os.makedirs(log_directory, exist_ok=True)

    filename = f"{log_directory}/{current_date}.log"

    with open(filename, 'a') as f:
        if os.stat(filename).st_size != 0:
            f.write('\n')
        f.write(packet.summary())
    print(F"Packet info written to: {filename}\n")


def ip_whitelisting(ip_address):
    if ip_address is not None and ip_address not in ip_whitelist:
        ip_whitelist.add(ip_address)
        print(f"IP: {ip_address} added to the whitelist")

    return ip_whitelist


# Detects SYN Flood Attack based on given timeframe and threshold
def syn_flood(packet, ip_whitelist):
    if packet.haslayer('TCP') and packet.haslayer('IP'):
        source_ip = packet['IP'].src
        dst_ip = packet['IP'].dst

        current_time = time.time()

        if source_ip not in ip_whitelist:
            if packet['TCP'].flags == 'S':
                syn_count[source_ip].append(current_time)
                syn_count[source_ip] = [t for t in syn_count[source_ip] if current_time - t < constants.TIMEFRAME]

                pending_handshake[(source_ip, dst_ip)].append(current_time)

                while pending_handshake[(source_ip, dst_ip)] and current_time - pending_handshake[(source_ip, dst_ip)][0] > constants.TIMEFRAME:
                    pending_handshake[(source_ip, dst_ip)].popleft()

                if len(syn_count[source_ip]) > constants.FLOOD_THRESHOLD or len(pending_handshake[(source_ip, dst_ip)]) > constants.MAX_PENDING:
                    if source_ip != local_ip:
                        print(f"***ALERT*** SYN Flood Attack detected from: {source_ip}")
                        write_to_log(packet)

            elif packet['TCP'].flags == 'A':
                if (source_ip, dst_ip) in pending_handshake:
                    if pending_handshake[(source_ip, dst_ip)]:
                        pending_handshake[(source_ip, dst_ip)].popleft()    
                

# Detects UDP Flood Attack based on given timeframe and threshold
def udp_flood(packet, ip_whitelist):
    if packet.haslayer('UDP') and packet.haslayer('IP'):
        whitelisted_port = [53, 123, 56976]

        source_ip = packet['IP'].src
        dst_port = packet['IP'].dport
        current_time = time.time()

        if source_ip not in ip_whitelist:
            if (dst_port not in whitelisted_port):
                udp_count[source_ip].append(current_time)
                udp_count[source_ip] = [t for t in udp_count[source_ip] if current_time - t < constants.TIMEFRAME]

            if len(udp_count[source_ip]) > constants.FLOOD_THRESHOLD:
                if source_ip != local_ip:
                    print(f"***ALERT*** UDP Flood Attack detected from {source_ip}")
                    write_to_log(packet)


# Detects ICMP Flood Attack based on given timeframe and threshold
def icmp_flood(packet, ip_whitelist):
    if packet.haslayer('ICMP') and packet.haslayer('IP'):
        source_ip = packet['IP'].src
        current_time = time.time()


        if source_ip not in ip_whitelist:
            icmp_count[source_ip].append(current_time)
            icmp_count[source_ip] = [t for t in icmp_count[source_ip] if current_time - t < constants.TIMEFRAME]

            if len(icmp_count[source_ip]) > constants.FLOOD_THRESHOLD:
                if (source_ip != local_ip and source_ip not in ip_whitelist):
                    print(f"***ALERT*** ICMP Flood Attack detected from: {source_ip}")
                    write_to_log(packet)


def ping_of_death(packet, ip_whitelist):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        source_ip = ip_layer.src
        size = ip_layer.len

        if size > 65535  and source_ip not in ip_whitelist:
            print(f"***ALERT*** Ping of Death detected: Oversized packet from: {ip_layer.src}, packet size: {size} bytes")
            write_to_log(packet)


def type_flood(packet, ip_whitelist):
    syn_flood(packet, ip_whitelist)
    udp_flood(packet, ip_whitelist)
    icmp_flood(packet, ip_whitelist)
    ping_of_death(packet, ip_whitelist)


def tcp_connect_scan(packet, ip_whitelist):
    if packet.haslayer('TCP') and packet.haslayer('IP'):
        source_ip = packet['IP'].src
        tcp_layer = packet['TCP']
        dst_port = tcp_layer.dport
        current_time = time.time()

        if tcp_layer.flags == "A":
            completed_handshake[source_ip][dst_port] = current_time

            completed_handshake[source_ip] = {
                port: timestamp
                for port, timestamp in completed_handshake[source_ip].items()
                if current_time - timestamp <= constants.TIMEFRAME
            }

            if len(completed_handshake[source_ip]) > constants.SCAN_THRESHOLD:
                print(f"TCP Connect Scan detected from {source_ip}. "
                      f"Scanned ports: {list(completed_handshake[source_ip].keys())}")


def syn_scan(packet, ip_whitelist):
    if packet.haslayer('TCP'):
        if packet['TCP'].flags == "S":
            source_ip = packet['IP'].src
            dst_port = packet['TCP'].dport
            key = (source_ip, dst_port)
            
            syn_scans[key] = syn_scans.get(key, 0) + 1
            
            if syn_scans[key] > constants.SCAN_THRESHOLD:
                print(f"SYN Scan detected: {source_ip} → Port {dst_port}")



def xmas_scan(packet, ip_whitelist):
    if packet.haslayer('TCP'):
        tcp_flags = packet['TCP'].flags
        if 'F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags:
            source_ip = packet['IP'].src
            dst_port = packet['TCP'].dport
            print(f"Xmas Scan detected: {source_ip} → Port {dst_port}")



def null_scan(packet, ip_whitelist):
    if packet.haslayer('TCP'):
        tcp_flags = packet['TCP'].flags
        if tcp_flags == 0:  # No flags set
            source_ip = packet['IP'].src
            dst_port = packet['TCP'].dport
            print(f"Null Scan detected: {source_ip} → Port {dst_port}")



def type_scan(packet, ip_whitelist):
    tcp_connect_scan(packet, ip_whitelist)
    syn_scan(packet, ip_whitelist)
    xmas_scan(packet, ip_whitelist)
    null_scan(packet, ip_whitelist)


def type_other(packet, ip_whitelist):
    pass


# Runs Attack Analyzer to detect different attacks, to be called when sniffing network traffic
def attack_analyzer(packet, ip_address=None):
    ip_whitelist = ip_whitelisting(ip_address)
    
    type_flood(packet, ip_whitelist)
    type_scan(packet, ip_whitelist)
    type_other(packet, ip_whitelist)
    