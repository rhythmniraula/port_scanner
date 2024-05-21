import tkinter as tk
from tkinter import ttk
import socket
import threading

class PortScannerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Port Scanner")
        self.master.geometry("400x300")

        self.target_label = ttk.Label(self.master, text="Enter Target(s):")
        self.target_label.pack(pady=5)
        self.target_entry = ttk.Entry(self.master, width=40)
        self.target_entry.pack(pady=5)

        self.ports_label = ttk.Label(self.master, text="Enter Number of Ports:")
        self.ports_label.pack(pady=5)
        self.ports_entry = ttk.Entry(self.master, width=40)
        self.ports_entry.pack(pady=5)

        self.scan_button = ttk.Button(self.master, text="Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        self.output_text = tk.Text(self.master, height=10, width=50)
        self.output_text.pack(pady=10)

    def start_scan(self):
        self.output_text.delete(1.0, tk.END)
        targets = self.target_entry.get()
        ports = int(self.ports_entry.get())

        if ',' in targets:
            self.output_text.insert(tk.END, "[*] Scanning Multiple Targets\n")
            for ip_addr in targets.split(','):
                self.scan(ip_addr.strip(), ports)
        else:
            self.scan(targets, ports)

    def scan(self, target, ports):
        self.output_text.insert(tk.END, '\n' + ' Starting Scan For ' + str(target) + '\n')
        for port in range(1, ports + 1):
            t = threading.Thread(target=self.scan_port, args=(target, port))
            t.start()
            

    def scan_port(self, ipaddress, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ipaddress, port))
            if result == 0:
                self.output_text.insert(tk.END, "[+] Port Opened " + str(port) + "\n")
            sock.close()
        except Exception as e:
            print(e)

def main():
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
