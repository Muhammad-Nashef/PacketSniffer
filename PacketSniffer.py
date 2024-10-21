from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP
import sqlite3
import tkinter as tk
import threading
import pandas as pd
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS

protocol_mapping = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: 'IGMP',
    50: 'ESP',
    51: 'AH',
    132: 'SCTP'
}


def get_protocol_name(protocol_number):
    """Get the protocol name from the protocol number."""
    return protocol_mapping.get(protocol_number, "Unknown")


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")

        # Define UI buttons
        self.start_button = tk.Button(root, text="Start", command=self.start_sniffing, width=10)
        self.start_button.grid(row=0, column=0, padx=10, pady=10)

        self.stop_button = tk.Button(root, text="Stop", command=self.stop_sniffing, width=10, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=10, pady=10)

        self.exit_button = tk.Button(root, text="Exit", command=self.exit_app, width=10)
        self.exit_button.grid(row=0, column=2, padx=10, pady=10)

        # Thread and control flag for sniffing
        self.sniff_thread = None
        self.sniffing = False

        self.db_name = 'network_packets.db'

    def save_packet_to_db(self, src_ip, dest_ip, protocol, length):
        """Save packet information to SQLite database."""
        conn = sqlite3.connect(self.db_name)  # Create a new connection for this thread
        cursor = conn.cursor()
        cursor.execute('INSERT INTO packets (src_ip, dest_ip, protocol,length) VALUES (?, ?, ?, ?)',
                       (src_ip, dest_ip, protocol, length))
        conn.commit()
        conn.close()

    def packet_callback(self, packet):
        """Callback function for packet sniffing."""
        if IP in packet:
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = packet.proto
            length = len(packet)

            if packet.haslayer(TCP):
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    print(f"HTTP Packet: {src_ip} -> {dest_ip}")
                else:
                    print(f"TCP Packet: {src_ip} -> {dest_ip}")

            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors='ignore')
                if "HTTP" in payload:
                    print(f"Detected HTTP Traffic: {src_ip} -> {dest_ip}")
                    if packet.haslayer(HTTPRequest):
                        method = packet[HTTPRequest].Method.decode()
                        host = packet[HTTPRequest].Host.decode()
                        path = packet[HTTPRequest].Path.decode()
                        http_info = f"HTTP Request: {method} {host}{path}"
                        print(http_info)
                    elif packet.haslayer(HTTPResponse):
                        status_code = packet[HTTPResponse].Status_Code.decode()
                        http_info = f"HTTP Response: {status_code}"
                        print(http_info)

            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                # Check if it's a DNS query
                if dns_layer.qr == 0:  # Query
                    dns_query = dns_layer.qd.qname.decode() if dns_layer.qd else ""
                    print(f"DNS Query: {dns_query} from {src_ip}")

                # Check if it's a DNS response
                elif dns_layer.qr == 1:  # Response
                    if dns_layer.an and hasattr(dns_layer.an, 'rdata'):
                        dns_response = dns_layer.an.rdata if dns_layer.an.rdata else ""
                        print(f"DNS Response: {dns_response} to {src_ip}")
                    else:
                        print(f"DNS Response: No answers for {src_ip}")

            self.save_packet_to_db(src_ip, dest_ip, get_protocol_name(protocol), length)

    def start_sniffing(self):
        """Start the sniffing process in a separate thread."""
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            print("Starting packet capture...")
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.daemon = True  # Ensure the thread exits with the program
            self.sniff_thread.start()

    def stop_sniffing(self):
        """Stop the sniffing process."""
        if self.sniffing:
            self.sniffing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            print("Stopped packet capture.")

    def sniff_packets(self):
        """Sniff packets until stopped."""
        while self.sniffing:
            sniff(prn=self.packet_callback, store=False, count=1)  # Capture packets one by one

    def exit_app(self):
        """Exit the application."""
        self.stop_sniffing()  # Ensure sniffing is stopped before exiting
        print("Exiting application...")

        # Connect to the database
        conn = sqlite3.connect('network_packets.db')

        # Load packet data into a DataFrame
        df = pd.read_sql_query("SELECT * FROM packets", conn)

        # Export to CSV
        df.to_csv('packet_logs.csv', index=False)
        print("Packet logs exported to 'packet_logs.csv'")
        conn.commit()
        conn.close()

        self.root.quit()

# Initialize the GUI application


if __name__ == "__main__":
    main_root = tk.Tk()
    app = PacketSnifferApp(main_root)
    main_root.mainloop()
