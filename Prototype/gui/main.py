import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff
import threading
import sys
import os

detector_path = os.path.abspath("../")
sys.path.append(detector_path)

import detector
import pcap_reader

def toggle_file_upload():
    if analysis_mode.get() == "pcap":
        file_button.pack(pady=10, before=start_button)
        file_label.pack(pady=5, before=start_button)

        delivery_label.pack_forget()
        gui_checkbox.pack_forget()
        log_checkbox.pack_forget()
        email_checkbox.pack_forget()
        
        gui_display_var.set(True)
        log_var.set(False)
        email_var.set(False)
        
        validate_start_button() 
    else:
        file_button.pack_forget()
        file_label.pack_forget()
        selected_file.set("")

        delivery_label.pack(pady=10, before=alert_frame)
        gui_checkbox.pack(side=tk.LEFT, padx=10)
        log_checkbox.pack(side=tk.LEFT, padx=10)
        email_checkbox.pack(side=tk.LEFT, padx=10)

        validate_start_button()

def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        selected_file.set(file_path)
        file_label.config(text=f"Selected File: {file_path}")

    validate_start_button()

def validate_start_button():
    if analysis_mode.get() == "pcap":
        if not selected_file.get():
            start_button.config(state=tk.DISABLED)
        else:
            start_button.config(state=tk.NORMAL)
    else:
        if gui_display_var.get() or log_var.get() or email_var.get():
            start_button.config(state=tk.NORMAL)
        else:
            start_button.config(state=tk.DISABLED)

def start_analysis():
    if analysis_mode.get() == "real-time":
        global ip_whitelist, analysis_mode_selected, alert_methods
        
        ip_whitelist = list(ip_list.get(0, tk.END))
        analysis_mode_selected = analysis_mode.get()
        alert_methods = []
        if gui_display_var.get():
            alert_methods.append("GUI Display")
        if log_var.get():
            alert_methods.append("Log")
        if email_var.get():
            alert_methods.append("Email")
        
        root.withdraw()
        open_realtime_page()
        
        threading.Thread(target=run_realtime_analysis, daemon=True).start()
    else:
        file_path = selected_file.get()
        if not os.path.exists(file_path):
            print("ERROR: File not found, please check file path and try again.\n")
            sys.exit(1)

        print(f"Analyizing {file_path}...\n")

        root.withdraw()
        open_pcap_page()

        # pcap_reader.run_pcap_analyzer(file_path)
        

def open_realtime_page():
    global alert_label, analysis_window
    
    analysis_window = tk.Toplevel(root)
    analysis_window.title("Real-Time Analysis")
    analysis_window.geometry("1200x800")
    
    ttk.Label(analysis_window, text="Real-Time Alerts", font=("Arial", 16)).pack(pady=20)
    
    alert_label = ttk.Label(analysis_window, text="No threats detected...", font=("Arial", 14), foreground="green")
    alert_label.pack(pady=20)
    
    stop_button = ttk.Button(analysis_window, text="Stop IDS", command=stop_analysis, style="TButton")
    stop_button.pack(pady=20)

def open_pcap_page():
    global alert_label, pcap_window
    ip_whitelist = list(ip_list.get(0, tk.END))

    pcap_window = tk.Toplevel(root)
    pcap_window.title("PCAP Analysis")
    pcap_window.geometry("1200x800")
    
    ttk.Label(pcap_window, text="PCAP Analysis Results", font=("Arial", 16)).pack(pady=20)
    
    # alert_label = ttk.Label(pcap_window, text="Analysis in progress...", font=("Arial", 14), foreground="green")
    # alert_label.pack(pady=20)
    
    file_path = selected_file.get()

    # SYN Flood
    syn_flood, detected = pcap_reader.syn_flood_pcap(file_path, ip_whitelist)
    if detected:
        syn_flood_label = ttk.Label(pcap_window, text=syn_flood, font=("Arial", 13))
        syn_flood_label.pack()
    else:
        syn_flood_label = ttk.Label(pcap_window, text=syn_flood, font=("Arial", 13))
        syn_flood_label.pack()

    # UDP Flood
    udp_flood = pcap_reader.udp_flood_pcap(file_path, ip_whitelist)
    udp_flood_label = ttk.Label(pcap_window, text=udp_flood, font=("Arial", 13))
    udp_flood_label.pack()

    # ICMP Flood
    icmp_flood = pcap_reader.icmp_flood_pcap(file_path, ip_whitelist)
    icmp_flood_label = ttk.Label(pcap_window, text=icmp_flood, font=("Arial", 13))
    icmp_flood_label.pack()

    # TCP Connect Scan
    tcp_connect_scan = pcap_reader.tcp_connect_scan_pcap(file_path, ip_whitelist)
    tcp_connect_scan_label = ttk.Label(pcap_window, text=tcp_connect_scan, font=("Arial", 13))
    tcp_connect_scan_label.pack()

    # SYN Scan
    syn_scan = pcap_reader.syn_scan_pcap(file_path, ip_whitelist)
    syn_scan_label = ttk.Label(pcap_window, text=syn_scan, font=("Arial", 13))
    syn_scan_label.pack()

    # X-Mas scan
    xmas_scan = pcap_reader.xmas_scan_pcap(file_path, ip_whitelist)
    xmas_scan_label = ttk.Label(pcap_window, text=xmas_scan, font=("Arial", 13))
    xmas_scan_label.pack()

    # Null Scan
    null_scan = pcap_reader.null_scan_pcap(file_path, ip_whitelist)
    null_scan_label = ttk.Label(pcap_window, text=null_scan, font=("Arial", 13))
    null_scan_label.pack()

    # DNS/ARP Spoofing 
    dns_arp_spoof = pcap_reader.dns_arp_spoof_pcap(file_path, ip_whitelist)
    dns_arp_spoof_label = ttk.Label(pcap_window, text=dns_arp_spoof, font=("Arial", 13))
    dns_arp_spoof_label.pack()

    # SSH Brute Force
    ssh_brute_force = pcap_reader.ssh_brute_force_pcap(file_path, ip_whitelist)
    ssh_brute_force_label = ttk.Label(pcap_window, text=ssh_brute_force, font=("Arial", 13))
    ssh_brute_force_label.pack()

    # Command Injection 
    command_injection = pcap_reader.command_injection_pcap(file_path, ip_whitelist)
    command_injection_label = ttk.Label(pcap_window, text=command_injection, font=("Arial", 13))
    command_injection_label.pack()

    # SQL Injection
    sql_injection = pcap_reader.sql_injection_pcap(file_path, ip_whitelist)
    sql_injection_label = ttk.Label(pcap_window, text=sql_injection, font=("Arial", 13))
    sql_injection_label.pack()


    stop_button = ttk.Button(pcap_window, text="Go Back", command=stop_analysis, style="TButton")
    stop_button.pack(pady=20)

def run_realtime_analysis():
    sniff_running = True

    while sniff_running:
        sniff(prn=process_packet, store=0)

def process_packet(packet):
    gui_display = gui_display_var.get()
    log = log_var.get()
    email = email_var.get()

    alert = detector.attack_analyzer(packet, whitelisted_ip, log, gui_display, email)
    
    if alert:
        print(f"Alert generated: {alert}")
        root.after(0, update_alert, alert)

def update_alert(alert):
    alert_label.config(text=alert, foreground="red")

def stop_analysis():
    if analysis_mode.get() == "real-time":
        sniff_running = False
        analysis_window.destroy()
        root.deiconify()
    else:
        pcap_window.destroy()
        root.deiconify()

def add_ip():
    ip = ip_entry.get()
    if ip and ip not in ip_list.get(0, tk.END):
        ip_list.insert(tk.END, ip)
        whitelisted_ip.add(ip)
    ip_entry.delete(0, tk.END)

def main():
    global root, ip_entry, ip_list, analysis_mode, selected_file, file_button, start_button, file_label
    global whitelisted_ip

    global gui_display_var, log_var, email_var
    global gui_display, log, email
    global delivery_label, gui_checkbox, log_checkbox, email_checkbox, alert_frame

    global sniff_running

    whitelisted_ip = set()

    gui_display = False
    log = False
    email = False

    root = tk.Tk()
    root.title("Custom IDS")
    root.geometry("1200x800")
    
    style = ttk.Style()
    style.configure("TButton", font=("Arial", 14), padding=10)
    style.configure("TRadiobutton", font=("Arial", 14))
    
    ip_frame = ttk.Frame(root)
    ip_frame.pack(pady=10)
    ttk.Label(ip_frame, text="Whitelist IP Address:", font=("Arial", 14)).pack(side=tk.LEFT)
    ip_entry = ttk.Entry(ip_frame, font=("Arial", 14), width=20)
    ip_entry.pack(side=tk.LEFT, padx=10)
    ip_add_button = ttk.Button(ip_frame, text="Add", command=add_ip, style="TButton")
    ip_add_button.pack(side=tk.LEFT)
    
    ip_list_frame = ttk.Frame(root)
    ip_list_frame.pack(pady=10, padx=50, fill=tk.X)
    ip_list = tk.Listbox(ip_list_frame, height=10, font=("Arial", 14), width=50, justify=tk.CENTER)
    ip_list.pack()
    
    analysis_mode = tk.StringVar(value="real-time")
    ttk.Label(root, text="Select Analysis Mode:", font=("Arial", 14)).pack(pady=10)
    ttk.Radiobutton(root, text="Real-time", variable=analysis_mode, value="real-time", command=toggle_file_upload, style="TRadiobutton").pack()
    ttk.Radiobutton(root, text="PCAP Analysis", variable=analysis_mode, value="pcap", command=toggle_file_upload, style="TRadiobutton").pack()
    
    selected_file = tk.StringVar()
    file_button = ttk.Button(root, text="Upload PCAP File", command=select_file, style="TButton")
    file_label = ttk.Label(root, text="", font=("Arial", 12))
    
    delivery_label = ttk.Label(root, text="Select Alert Delivery Method:", font=("Arial", 14))
    delivery_label.pack(pady=10)
    gui_display_var = tk.BooleanVar(value=False)
    log_var = tk.BooleanVar(value=False)
    email_var = tk.BooleanVar(value=False)
    
    alert_frame = ttk.Frame(root)
    alert_frame.pack(pady=10)
    
    gui_checkbox = ttk.Checkbutton(alert_frame, text="GUI Display", variable=gui_display_var, command=validate_start_button)
    gui_checkbox.pack(side=tk.LEFT, padx=10)
    log_checkbox = ttk.Checkbutton(alert_frame, text="Log", variable=log_var, command=validate_start_button)
    log_checkbox.pack(side=tk.LEFT, padx=10)
    email_checkbox = ttk.Checkbutton(alert_frame, text="Email", variable=email_var, command=validate_start_button)
    email_checkbox.pack(side=tk.LEFT, padx=10)
    
    start_button = ttk.Button(root, text="Start IDS", command=start_analysis, style="TButton")
    start_button.pack(pady=20)
    
    root.mainloop()

if __name__ == "__main__":
    main()
