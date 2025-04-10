# Packet-Sniffer-Gui
A Packet Sniffer is a network analysis tool used to monitor, intercept, and log traffic passing over a digital network.


This project is a custom-built packet sniffing application designed to provide users with deep insights into the data flowing across their network interfaces. 
It captures packets in real-time, decodes protocol layers, and presents the information in a human-readable format, making it an essential tool for network administrators, cybersecurity professionals, and developers.

🚀 About the Project
This repository contains a lightweight yet powerful Packet Sniffer built to analyze raw network traffic. 
It operates at the data link layer and captures all packets transmitted over the selected network interface. 
The tool then parses and displays information from various protocol headers such as Ethernet, IP, TCP, UDP, ICMP, and more.

The goal of this project is to offer a transparent view into network communications for educational, diagnostic, and security purposes. 
Whether you're troubleshooting a network issue or learning how data flows across a network, this packet sniffer is a helpful companion.



✨ Features
Real-time packet capturing

Support for multiple protocols (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, etc.)

Detailed parsing of packet headers and payloads

Filtering capabilities (by protocol, port, IP address, etc.)

Graphical User Interface

Option to save captured data to a file (e.g., .pcap format)

Lightweight and efficient, with minimal dependencies

🔧 Technologies Used
Programming Language: Python 

Socket Programming (Raw sockets)

Struct and binascii modules for data decoding

Optional: Scapy or libpcap/winpcap for advanced capture and filtering

Note: Depending on the platform, administrative or root privileges may be required to capture packets.

📦 Installation

git clone https://github.com/Iankulani/Packet-Sniffer-Gui.git

sudo python Packet-Sniffer-Gui

![Screenshot_2025-04-09_22_36_42](https://github.com/user-attachments/assets/7ba0b7d6-18e8-44ba-9efa-a48e28018611)


🛠 Use Cases
Network Diagnostics: Detect anomalies or connection issues in real time.

Security Auditing: Monitor for suspicious or unauthorized traffic.

Educational Purposes. Understand how network protocols function at a low level.

Application Debugging: Analyze how your software communicates over the network.

📌 Disclaimer
This tool is intended for educational and authorized use only. Unauthorized interception of network traffic may violate privacy laws and terms of service. 
Always ensure you have permission to monitor any network you're analyzing.

🤝 Contributions
Contributions are welcome! If you have suggestions for improvements or want to add more protocol support or features, feel free to fork the project and create a pull request.
