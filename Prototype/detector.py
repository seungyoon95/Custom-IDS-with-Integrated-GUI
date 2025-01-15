import constants


from datetime import datetime
import time
import os
import socket
from collections import defaultdict, deque
from scapy.layers.inet import IP


# Dictionaries to hold packet counts from 
syn_count = defaultdict(list)
udp_count = defaultdict(list)
icmp_count = defaultdict(list)

pending_handshake = defaultdict(deque)


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


# Detects SYN Flood Attack based on given timeframe and threshold
def syn_flood(packet):
    if packet.haslayer('TCP') and packet.haslayer('IP'):
        source_ip = packet['IP'].src
        dst_ip = packet['IP'].dst

        current_time = time.time()

        if packet['TCP'].flags == 'S':
            syn_count[source_ip].append(current_time)
            syn_count[source_ip] = [t for t in syn_count[source_ip] if current_time - t < constants.TIMEFRAME]

            pending_handshake[(source_ip, dst_ip)].append(current_time)

            # Remove old SYNs from the queue
            while pending_handshake[(source_ip, dst_ip)] and current_time - pending_handshake[(source_ip, dst_ip)][0] > constants.TIMEFRAME:
                pending_handshake[(source_ip, dst_ip)].popleft()

            # Check for SYN flood
            if len(syn_count[source_ip]) > constants.THRESHOLD or len(pending_handshake[(source_ip, dst_ip)]) > constants.MAX_PENDING:
                if source_ip != local_ip:
                    print(f"***ALERT*** SYN Flood Attack detected from: {source_ip}")
                    write_to_log(packet)

            # Check if this is an ACK packet (ACK flag set, SYN flag not set)
        elif packet['TCP'].flags == 'A':
            if (source_ip, dst_ip) in pending_handshake:
                if pending_handshake[(source_ip, dst_ip)]:
                    # Remove the oldest pending SYN since it has been acknowledged
                    pending_handshake[(source_ip, dst_ip)].popleft()    

        # if len(syn_count[source_ip]) > constants.THRESHOLD:
        #     if source_ip != local_ip:
        #         print(f"***ALERT*** SYN Flood Attack detected from: {source_ip}")
        #         write_to_log(packet)
                

# Detects UDP Flood Attack based on given timeframe and threshold
def udp_flood(packet):
    if packet.haslayer('UDP') and packet.haslayer('IP'):
        whitelisted_port = [53, 123]

        source_ip = packet['IP'].src
        dst_port = packet['IP'].dport
        current_time = time.time()

        if (dst_port not in whitelisted_port):
            udp_count[source_ip].append(current_time)
            udp_count[source_ip] = [t for t in udp_count[source_ip] if current_time - t < constants.TIMEFRAME]

        if len(udp_count[source_ip]) > constants.THRESHOLD:
            if source_ip != local_ip:
                print(f"***ALERT*** UDP Flood Attack detected from {source_ip}")
                write_to_log(packet)


# Detects ICMP Flood Attack based on given timeframe and threshold
def icmp_flood(packet):
    if packet.haslayer('ICMP') and packet.haslayer('IP'):
        source_ip = packet['IP'].src
        current_time = time.time()

        icmp_count[source_ip].append(current_time)
        icmp_count[source_ip] = [t for t in icmp_count[source_ip] if current_time - t < constants.TIMEFRAME]

        if len(icmp_count[source_ip]) > constants.THRESHOLD:
            if (source_ip != local_ip):
                print(f"***ALERT*** ICMP Flood Attack detected from: {source_ip}")
                write_to_log(packet)


def ping_of_death(packet):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']

        size = ip_layer.len

        if size > 65535:
            print(f"***ALERT*** Ping of Death detected: Oversized packet from: {ip_layer.src}, packet size: {size} bytes")
            write_to_log(packet)


# Runs Attack Analyzer to detect different attacks, to be called when sniffing network traffic
def attack_analyzer(packet):
    syn_flood(packet)
    udp_flood(packet)
    icmp_flood(packet)
    ping_of_death(packet)
