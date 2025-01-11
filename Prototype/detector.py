import constants


from datetime import datetime
import time
import os
import socket
from collections import defaultdict


local_ip = socket.gethostbyname(socket.gethostname())


# Dictionaries to hold packet counts from 
syn_count = defaultdict(list)
udp_count = defaultdict(list)
icmp_count = defaultdict(list)


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
        current_time = time.time()

        syn_count[source_ip].append(current_time)
        syn_count[source_ip] = [t for t in syn_count[source_ip] if current_time - t < constants.TIMEFRAME]

        if len(syn_count[source_ip]) > constants.THRESHOLD:
            if source_ip != local_ip:
                print(f"***ALERT*** SYN Flood Attack detected from: {source_ip}")
                write_to_log(packet)
                

# Detects UDP Flood Attack based on given timeframe and threshold
def udp_flood(packet):
    if packet.haslayer('UDP') and packet.haslayer('IP'):
        source_ip = packet['IP'].src
        current_time = time.time()

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


# To Be Implemented
def port_scan(packet):
    pass


# To be Implemented
def arp_spoof(packet):
    pass


# To be Implemented
def http_flood(packet):
    pass


# Runs Attack Analyzer to detect different attacks, to be called when sniffing network traffic
def attack_analyzer(packet):
    syn_flood(packet)
    udp_flood(packet)
    icmp_flood(packet)
    port_scan(packet)
    arp_spoof(packet)
    http_flood(packet)