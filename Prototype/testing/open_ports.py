import socket
import threading

def start_server(port):
    """Function to create a server socket on a specific port"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse
        s.bind(("0.0.0.0", port))  # Bind to all network interfaces
        s.listen()
        print(f"Listening on port {port}...")
        while True:
            conn, addr = s.accept()
            print(f"Connection received on port {port} from {addr}")
            conn.close()

# Open ports from 1000 to 10010
for port in range(20000, 20011):
    threading.Thread(target=start_server, args=(port,), daemon=True).start()

# Keep the script running
input("Press Enter to stop the servers...\n")
