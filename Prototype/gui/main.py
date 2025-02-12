import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff
import threading
import sys
import os

detector_path = os.path.abspath("../")
sys.path.append(detector_path)

import detector

def toggle_file_upload():
    if analysis_mode.get() == "pcap":
        file_button.pack(pady=10, before=start_button)
        file_label.pack(pady=5, before=start_button)
    else:
        file_button.pack_forget()
        file_label.pack_forget()
        selected_file.set("")

def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        selected_file.set(file_path)
        file_label.config(text=f"Selected File: {file_path}")

def validate_start_button():
    if gui_display_var.get() or log_var.get() or email_var.get():
        start_button.config(state=tk.NORMAL)
    else:
        start_button.config(state=tk.DISABLED)

def start_analysis():
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
    open_analysis_page()
    
    if analysis_mode_selected == "real-time":
        threading.Thread(target=run_realtime_analysis, daemon=True).start()

def open_analysis_page():
    global alert_label, analysis_window
    
    analysis_window = tk.Toplevel(root)
    analysis_window.title("IDS Analysis")
    analysis_window.geometry("1200x800")
    
    ttk.Label(analysis_window, text="Alerts", font=("Arial", 16)).pack(pady=20)
    
    alert_label = ttk.Label(analysis_window, text="No threats detected...", font=("Arial", 14), foreground="green")
    alert_label.pack(pady=20)
    
    stop_button = ttk.Button(analysis_window, text="Stop IDS", command=stop_analysis, style="TButton")
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
    sniff_running = False
    analysis_window.destroy()
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
    
    ttk.Label(root, text="Select Alert Delivery Method:", font=("Arial", 14)).pack(pady=10)
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

    validate_start_button()
    
    root.mainloop()

if __name__ == "__main__":
    main()
