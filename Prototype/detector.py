import constants

from datetime import datetime
import time
import os
import socket
from collections import defaultdict, deque


# Dictionaries to hold packet counts from 
syn_count = defaultdict(list)
udp_count = defaultdict(lambda: {"sent": [], "received": []})
icmp_count = defaultdict(list)



pending_handshake = defaultdict(deque)

completed_handshake = defaultdict(dict)
syn_scans = {}

ip_whitelist = set()

# Host IP address
local_ip = socket.gethostbyname(socket.gethostname())


# Writes packet info to a log file
def write_to_log(attack_type, packet):
    print("\n===========================================")
    print(datetime.now())
    print(f"Attack Type: {attack_type}")
    print(f"Source IP and Port: {packet['IP'].src}:{packet['IP'].sport}")
    print(f"Destination IP and Port: {packet['IP'].dst}:{packet['IP'].dport}")

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
        f.write(f"\nSource IP and Port: {packet['IP'].src}:{packet['IP'].sport}")
        f.write(f"\nDestination IP and Port: {packet['IP'].dst}:{packet['IP'].dport}")
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
                        write_to_log("SYN FLOOD", packet)

            elif packet['TCP'].flags == 'A':
                if (source_ip, dst_ip) in pending_handshake:
                    if pending_handshake[(source_ip, dst_ip)]:
                        pending_handshake[(source_ip, dst_ip)].popleft()    
                

# Detects UDP Flood Attack based on given timeframe and threshold
def udp_flood(packet, ip_whitelist):
    if packet.haslayer('UDP') and packet.haslayer('IP'):
        whitelisted_port = [53, 123, 443, 56976]

        source_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        dst_port = packet['IP'].dport
        current_time = time.time()

        if source_ip not in udp_count:
            udp_count[source_ip] = {"sent": [], "received": []}
        if dst_ip not in udp_count:
            udp_count[dst_ip] = {"sent": [], "received": []}

        udp_count[source_ip]["sent"] = [t for t in udp_count[source_ip]["sent"] if current_time - t < constants.TIMEFRAME]
        udp_count[dst_ip]["received"] = [t for t in udp_count[dst_ip]["received"] if current_time - t < constants.TIMEFRAME]

        if source_ip not in ip_whitelist and dst_port not in whitelisted_port:
            udp_count[source_ip]["sent"].append(current_time)

            # Determine incoming/outgoing packet ratio
            sent_count = len(udp_count[source_ip]["sent"])
            received_count = len(udp_count[source_ip]["received"])  

            # Trigger an alert if outgoing packets significantly exceed incoming responses
            if sent_count > constants.FLOOD_THRESHOLD and (received_count == 0 or sent_count / max(received_count, 1) > constants.FLOOD_RATIO_THRESHOLD):
                if source_ip != local_ip:
                    write_to_log("UDP FLOOD", packet)


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
                    write_to_log("ICMP FLOOD", packet)


def ping_of_death(packet, ip_whitelist):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        source_ip = ip_layer.src
        size = ip_layer.len

        if size > 65535  and source_ip not in ip_whitelist:
            write_to_log("PING OF DEATH", packet)


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

            if len(completed_handshake[source_ip]) > constants.SCAN_THRESHOLD and source_ip not in ip_whitelist:
                write_to_log("TCP CONNECT SCAN", packet)


def syn_scan(packet, ip_whitelist):
    whitelisted_port = [53, 80, 443]

    if packet.haslayer('TCP'):
        if packet['TCP'].flags == "S":
            source_ip = packet['IP'].src
            dst_port = packet['TCP'].dport
            key = (source_ip, dst_port)
            
            syn_scans[key] = syn_scans.get(key, 0) + 1
            
            if syn_scans[key] > constants.SCAN_THRESHOLD and source_ip not in ip_whitelist and dst_port not in whitelisted_port:
                write_to_log("SYN SCAN", packet)



def xmas_scan(packet, ip_whitelist):
    if packet.haslayer('TCP'):
        tcp_flags = packet['TCP'].flags
        source_ip = packet['IP'].src
        if 'F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags and source_ip not in ip_whitelist:
            dst_port = packet['TCP'].dport
            write_to_log("XMAS SCAN", packet)



def null_scan(packet, ip_whitelist):
    if packet.haslayer('TCP'):
        tcp_flags = packet['TCP'].flags
        source_ip = packet['IP'].src
        if tcp_flags == 0 and source_ip not in ip_whitelist:
            dst_port = packet['TCP'].dport
            write_to_log("NULL SCAN", packet)



def type_scan(packet, ip_whitelist):
    tcp_connect_scan(packet, ip_whitelist)
    syn_scan(packet, ip_whitelist)
    xmas_scan(packet, ip_whitelist)
    null_scan(packet, ip_whitelist)


def dns_arp_spoof(packet, ip_whitelist):
    pass

def ssh_brute_force(packet, ip_whitelist):
    pass

def command_injection(packet, ip_whitelist):
    pass

def sql_injection(packet, ip_whitelist):
    pass

def type_other(packet, ip_whitelist):
    dns_arp_spoof(packet, ip_whitelist)
    ssh_brute_force(packet, ip_whitelist)
    command_injection(packet, ip_whitelist)
    sql_injection(packet, ip_whitelist)


# Runs Attack Analyzer to detect different attacks, to be called when sniffing network traffic
def attack_analyzer(packet, ip_address=None):
    ip_whitelist = ip_whitelisting(ip_address)
    
    type_flood(packet, ip_whitelist)
    type_scan(packet, ip_whitelist)
    type_other(packet, ip_whitelist)
    