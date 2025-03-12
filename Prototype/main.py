import detector
import pcap_reader


import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff
import threading
import time
import sys
import os


def toggle_email_entry():
    if email_var.get():
        email_label.pack(pady=5, before=start_button)
        email_entry.pack(pady=5, before=start_button)
    else:
        email_label.pack_forget()
        email_entry.pack_forget()
        email_entry.delete(0, tk.END)

    validate_start_button()

def toggle_file_upload():
    if analysis_mode.get() == "pcap":
        file_button.pack(pady=5, before=start_button)
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

def validate_ip_remove_button():
    selected_index = ip_list.curselection()
    if selected_index:
        ip_remove_button.config(state=tk.NORMAL)
    else:
        ip_remove_button.config(state=tk.DISABLED)

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
    analysis_window.geometry("600x800")

    top_bar = tk.Frame(analysis_window)
    top_bar.pack(fill=tk.X, padx=10, pady=5)

    ttk.Label(top_bar, text="Real-Time Alerts", font=("Arial", 16)).pack(side=tk.LEFT, pady=20)

    stop_button = ttk.Button(top_bar, text="Go Back", command=stop_analysis, style="TButton")
    stop_button.pack(pady=10, side=tk.RIGHT)

    if len(whitelisted_ip) != 0:
        whitelist_label = ttk.Label(analysis_window, text=f"Whitelisted IPs: {whitelisted_ip}", font=("Arial", 14), foreground="blue")
        whitelist_label.pack(pady=10)

    alert_label = ttk.Label(analysis_window, text="No threats detected...", font=("Arial", 14), foreground="green")
    alert_label.pack(pady=20)
    
def open_pcap_page():
    global alert_label, pcap_window
    
    pcap_window = tk.Toplevel(root)
    pcap_window.title("PCAP Analysis")
    pcap_window.geometry("600x800")

    top_bar = tk.Frame(pcap_window)
    top_bar.pack(fill=tk.X, padx=10, pady=5)

    ttk.Label(top_bar, text="PCAP Analysis Results", font=("Arial", 16)).pack(side=tk.LEFT, pady=20)
    
    stop_button = ttk.Button(top_bar, text="Go Back", command=stop_analysis, style="TButton")
    stop_button.pack(pady=10, side=tk.RIGHT)

    if len(whitelisted_ip) != 0:
        whitelist_label = ttk.Label(pcap_window, text=f"Whitelisted IPs: {whitelisted_ip}", font=("Arial", 14), foreground="blue")
        whitelist_label.pack(pady=10)

    ip_whitelist = list(ip_list.get(0, tk.END))

    file_path = selected_file.get()

    pcap_analysis = pcap_reader.run_pcap_analyzer(file_path, ip_whitelist)
    
    for alerts in pcap_analysis:
        alert_container = tk.Frame(pcap_window, bd=2, relief="ridge",padx=5, pady=5)
        alert_container.pack(fill="x", pady=5)

        for alert in alerts:
            alert_detail = tk.Label(alert_container, text=alert, fg="black", font=("Arial", 12, "bold"))
            alert_detail.pack(anchor="w", pady=2, padx=5)



def run_realtime_analysis():
    sniff_running = True

    while sniff_running:
        sniff(prn=process_packet, store=0)


def process_packet(packet):
    gui_display = gui_display_var.get()
    log = log_var.get()
    email = email_var.get()

    if email_var.get():
        user_email = email_entry.get().strip()
    else:
        user_email = None

    alert = detector.attack_analyzer(packet, whitelisted_ip, log, gui_display, email, user_email)
        
    if len(detector.shared_alert) != 0:
        alert_label.pack_forget()
    
        print("ALERT GENERATED!")
        print(detector.shared_alert)

        alert_container = tk.Frame(analysis_window, bd=2, relief="ridge",padx=5, pady=5)
        alert_container.pack(fill="x", pady=5)

        for alert in detector.shared_alert:
            alert_detail = tk.Label(alert_container, text=alert, fg="black", font=("Arial", 12, "bold"))
            alert_detail.pack(anchor="w", pady=2, padx=5)

        detector.shared_alert.clear()
    
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
        print(f"Current list of whitelisted IP: {whitelisted_ip}")
    ip_entry.delete(0, tk.END)

def remove_ip():
    try:
        selected_index = ip_list.curselection()
        if selected_index:
            ip_remove_button.config(state=tk.NORMAL)
            index = selected_index[0]
            ip_string = ip_list.get(index)
            ip_list.delete(index)
             
            if ip_string in whitelisted_ip:
                whitelisted_ip.discard(ip_string)
                print(f"Removed IP: {ip_string}")
            else:
                print(f"attempted to remove: {ip_string}")
                print(f"IP doesn't exist in set, current set: {whitelisted_ip}")
        else:
            ip_remove_button.config(state=tk.DISABLED)
    except IndexError:
        print("Error removing whitelisted IP")

def main():
    global root, ip_entry, ip_list, analysis_mode, selected_file, file_label
    global file_button, start_button, ip_remove_button
    global whitelisted_ip

    global gui_display_var, log_var, email_var
    global gui_display, log, email
    global delivery_label, gui_checkbox, log_checkbox, email_checkbox, alert_frame

    global email_label, email_entry

    global sniff_running

    sniff_running = False

    whitelisted_ip = set()

    gui_display = False
    log = False
    email = False

    root = tk.Tk()
    root.title("Custom IDS")
    root.geometry("600x800")
    
    style = ttk.Style()
    style.configure("TButton", font=("Arial", 14), padding=10)
    style.configure("TRadiobutton", font=("Arial", 14))
    
    ip_frame = ttk.Frame(root)
    ip_frame.pack(pady=10, padx=30)
    ttk.Label(ip_frame, text="Enter IP Address to whitelist below:", font=("Arial", 14), justify=tk.CENTER).pack(pady=10)

    ip_entry = ttk.Entry(ip_frame, font=("Arial", 14), width=30, justify=tk.CENTER)
    ip_entry.pack(side=tk.LEFT, pady=10, padx=10)
    
    button_frame = ttk.Frame(root)
    button_frame.pack(pady=10, padx=10)

    ip_add_button = ttk.Button(button_frame, text="Add", command=add_ip, style="TButton")
    ip_add_button.pack(side=tk.LEFT, padx=10)

    ip_remove_button = ttk.Button(button_frame, text="Remove", command=remove_ip, style="TButton")
    ip_remove_button.pack(side=tk.LEFT, padx=10)

    ip_list_frame = ttk.Frame(root)
    ip_list_frame.pack(pady=10)

    listbox_frame = ttk.Frame(ip_list_frame)
    listbox_frame.pack(fill=tk.X, expand=True)

    ip_list = tk.Listbox(listbox_frame, height=10, font=("Arial", 14), width=30, justify=tk.CENTER, selectmode=tk.SINGLE)
    ip_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=ip_list.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    ip_list.config(yscrollcommand=scrollbar.set)

    ip_list.config(
        fg="gray",
        selectbackground="darkblue",
        selectforeground="white",
        bd=1,
        relief="solid",
    )
    
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

    email_label = ttk.Label(root, text="Enter your email address below:")
    email_entry = ttk.Entry(root, width=30)
    email_checkbox.config(command=toggle_email_entry)

    start_button = ttk.Button(root, text="Start IDS", command=start_analysis, style="TButton")
    start_button.pack(pady=20)

    validate_start_button()
    
    root.mainloop()

if __name__ == "__main__":
    main()
