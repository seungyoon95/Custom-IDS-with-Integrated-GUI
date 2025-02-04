import tkinter as tk
from tkinter import ttk, filedialog

def toggle_file_upload():
    if analysis_mode.get() == "pcap":
        file_button.pack(pady=10, before=start_button)
    else:
        file_button.pack_forget()
        selected_file.set("")

def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        selected_file.set(file_path)

def start_analysis():
    ip = ip_entry.get()
    mode = analysis_mode.get()
    file = selected_file.get() if mode == "pcap" else None
    print(f"Starting {mode} analysis... (Whitelisted IP: {ip}, File: {file})")
    # IDS logic below

def add_ip():
    ip = ip_entry.get()
    if ip and ip not in ip_list.get(0, tk.END):
        ip_list.insert(tk.END, ip)
    ip_entry.delete(0, tk.END)

def main():
    global root, ip_entry, ip_list, analysis_mode, selected_file, file_button, start_button
    
    # Create the main application window
    root = tk.Tk()
    root.title("Custom IDS")
    root.geometry("1200x800")

    # Apply styles
    style = ttk.Style()
    style.configure("TButton", font=("Arial", 14), padding=10)
    style.configure("TRadiobutton", font=("Arial", 14))

    # IP Address Whitelist Frame
    ip_frame = ttk.Frame(root)
    ip_frame.pack(pady=10)
    ttk.Label(ip_frame, text="Whitelist IP Address:", font=("Arial", 14)).pack(side=tk.LEFT)
    ip_entry = ttk.Entry(ip_frame, font=("Arial", 14), width=20)
    ip_entry.pack(side=tk.LEFT, padx=10)
    ip_add_button = ttk.Button(ip_frame, text="Add", command=add_ip, style="TButton")
    ip_add_button.pack(side=tk.LEFT)

    # IP List Display Frame (Centered with margins)
    ip_list_frame = ttk.Frame(root)
    ip_list_frame.pack(pady=10, padx=50, fill=tk.X)
    ip_list = tk.Listbox(ip_list_frame, height=10, font=("Arial", 14), width=50, justify=tk.CENTER)
    ip_list.pack()

    # Analysis Mode Selection
    analysis_mode = tk.StringVar(value="real-time")
    ttk.Label(root, text="Select Analysis Mode:", font=("Arial", 14)).pack(pady=10)
    ttk.Radiobutton(root, text="Real-time Analysis", variable=analysis_mode, value="real-time", command=toggle_file_upload, style="TRadiobutton").pack()
    ttk.Radiobutton(root, text=".pcap Analysis", variable=analysis_mode, value="pcap", command=toggle_file_upload, style="TRadiobutton").pack()

    # File Upload Button (Initially Hidden)
    selected_file = tk.StringVar()
    file_button = ttk.Button(root, text="Upload .pcap File", command=select_file, style="TButton")

    # Start Button
    start_button = ttk.Button(root, text="Start IDS", command=start_analysis, style="TButton")
    start_button.pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    main()
