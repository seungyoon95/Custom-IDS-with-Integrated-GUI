import subprocess
import re
from scapy.all import conf

def get_mac(router_ip):
    # For Linux
    # command = f"arp -n {router_ip}"
    # For Windows
    command = f"arp -a {router_ip}"

    try:
        output = subprocess.check_output(command, shell=True, text=True)

        router_mac = re.search(r"([a-f0-9]{2}[:-]){5}[a-f0-9]{2}", output)
        if router_mac:
            return router_mac.group(0)
        else:
            return None
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None

router_ip = conf.route.route("0.0.0.0")[2]

router_mac = get_mac(router_ip)

print(f"Router IP: {router_ip}")
print(f"Router Mac Address: {router_mac}")