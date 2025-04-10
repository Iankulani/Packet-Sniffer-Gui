import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, Ether, IP
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class PacketSniffer:
    def __init__(self, ip_filter, mac_filter, gui_callback, update_pie_chart_callback):
        self.ip_filter = ip_filter
        self.mac_filter = mac_filter
        self.gui_callback = gui_callback
        self.update_pie_chart_callback = update_pie_chart_callback
        self.sniffing = False
        self.protocols = {}

    def packet_filter(self, packet):
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            if self.mac_filter and self.mac_filter.lower() not in [src_mac.lower(), dst_mac.lower()]:
                return False

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if self.ip_filter and self.ip_filter not in [src_ip, dst_ip]:
                return False

        return True

    def start_sniffing(self):
        self.sniffing = True
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing)

    def process_packet(self, packet):
        if self.packet_filter(packet):
            proto = packet[IP].proto if IP in packet else "N/A"
            if proto in self.protocols:
                self.protocols[proto] += 1
            else:
                self.protocols[proto] = 1

            self.update_pie_chart_callback(self.protocols)
            info = {
                "src_ip": packet[IP].src if IP in packet else "N/A",
                "dst_ip": packet[IP].dst if IP in packet else "N/A",
                "src_mac": packet[Ether].src if Ether in packet else "N/A",
                "dst_mac": packet[Ether].dst if Ether in packet else "N/A",
                "proto": proto
            }
            self.gui_callback(info)

    def stop_sniffing(self):
        self.sniffing = False


class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity IP/MAC Packet Monitor (Educational Only)")
        self.root.configure(bg="#006400")  # Dark Green Background

        self.sniffer = None

        label_style = {'bg': '#006400', 'fg': 'white', 'font': ('Helvetica', 10)}
        entry_style = {'bg': '#e0ffe0', 'fg': '#000000'}

        # Input Fields
        tk.Label(root, text="IP Address Filter (Optional):", **label_style).grid(row=0, column=0, pady=5, padx=5, sticky='w')
        self.ip_entry = tk.Entry(root, **entry_style)
        self.ip_entry.grid(row=0, column=1, pady=5, padx=5)

        tk.Label(root, text="MAC Address Filter (Optional):", **label_style).grid(row=1, column=0, pady=5, padx=5, sticky='w')
        self.mac_entry = tk.Entry(root, **entry_style)
        self.mac_entry.grid(row=1, column=1, pady=5, padx=5)

        # Buttons
        self.start_btn = tk.Button(root, text="Start Monitoring", command=self.start_monitoring,
                                   bg="#228B22", fg="white", font=("Helvetica", 10, "bold"))
        self.start_btn.grid(row=2, column=0, pady=10)

        self.stop_btn = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring,
                                  bg="#006400", fg="white", font=("Helvetica", 10, "bold"), state=tk.DISABLED)
        self.stop_btn.grid(row=2, column=1, pady=10)

        # Pie Chart (Matplotlib canvas)
        self.fig, self.ax = plt.subplots(figsize=(5, 4))
        self.ax.pie([], labels=[], autopct='%1.1f%%', startangle=90)
        self.ax.axis('equal')  # Equal aspect ratio ensures the pie is drawn as a circle.
        self.canvas = FigureCanvasTkAgg(self.fig, master=root)  # Matplotlib figure
        self.canvas.get_tk_widget().grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    def add_packet(self, packet_info):
        # Optional: Could display the packet information in a separate area, but we are focusing on the pie chart
        pass

    def update_pie_chart(self, protocol_data):
        # Update the pie chart with the current protocol data
        self.ax.clear()  # Clear previous chart data
        if protocol_data:
            self.ax.pie(protocol_data.values(), labels=protocol_data.keys(), autopct='%1.1f%%', startangle=90)
            self.ax.axis('equal')  # Equal aspect ratio ensures the pie is drawn as a circle.
        self.canvas.draw()

    def start_monitoring(self):
        ip_filter = self.ip_entry.get().strip()
        mac_filter = self.mac_entry.get().strip()

        self.sniffer = PacketSniffer(ip_filter, mac_filter, self.add_packet, self.update_pie_chart)
        self.sniff_thread = threading.Thread(target=self.sniffer.start_sniffing, daemon=True)
        self.sniff_thread.start()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

    def stop_monitoring(self):
        if self.sniffer:
            self.sniffer.stop_sniffing()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()
