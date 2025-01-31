import detector
import pcap_reader

from scapy.all import sniff
import signal
import os
import sys


"""
Signal handler to terminate program with KeyboardInterrupt
"""
def signal_handler(sig, frame):
    print("Terminating program...\n")
    sys.exit(0)

"""
For testing real-time IDS, ONLY enable one main() at a time
"""
# def main():
#     signal.signal(signal.SIGINT, signal_handler)

#     try:
#         print("\nReal-Time Detection started...\n")
#         sniff(prn=detector.attack_analyzer, store=0)
#     except Exception as e:
#        print(f"Error: {e}")


"""
For testing pcap analyzer, ONLY enable one main() at a time
"""
def main():
    pcap_file = './pcaps/syn_flood.pcap'

    if not os.path.exists(pcap_file):
        print("ERROR: File not found, please check file path and try again.\n")
        sys.exit(1)

    print(f"Analyizing {pcap_file}...\n")

    pcap_reader.run_pcap_analyzer(pcap_file)


if __name__ == "__main__":
    main()
