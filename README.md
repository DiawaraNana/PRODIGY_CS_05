# PRODIGY_CS_05
# Packet Sniffer Tool

## Overview

This Python-based packet sniffer captures and analyzes network packets in real-time. It displays relevant information such as source and destination IP addresses, protocols, ports, and payload data. This tool is intended strictly for educational and ethical purposes.

## Features

- Capture live network traffic from a specified interface.
- Display packet information including:
- Timestamp
- Source and destination IP addresses
- Protocol type (TCP, UDP, ICMP, or others)
- Source and destination ports (if applicable)
- Payload data in hexadecimal format (limited to 50 bytes for readability)
- Supports common protocols like TCP, UDP, ICMP, ESP, AH, and OSPF.

## Requirements
> - Python 3.x
> - Scapy library
> - Install Scapy using pip:
```bash
pip install scapy
```
## Usage

- Edit the interface:
Replace "eth0" in the script with your actual network interface name (e.g., wlan0 for Wi-Fi or en0 on macOS).

- Run the script:
  
```bash
sudo python3 packet_sniffer.py
```

**Note: sudo is required because packet sniffing often requires root privileges.**

## Output:
The script prints captured packet details in real-time, for example:

[2025-08-14 16:20:15.123] TCP Packet: 192.168.1.10:52345 -> 93.184.216.34:80 | Length: 60 bytes | Payload (hex): 474554202f20685454502f312e310d0a486f73743a20777777

[2025-08-14 16:20:16.456] ICMP Packet: 192.168.1.10 -> 8.8.8.8 Type: 8 | Length: 84 bytes | Payload (hex): 08007c4f1c3b000145676f6d657472696320

## Ethical Use

**This tool is intended only for learning, network analysis, or authorized penetration testing. Unauthorized interception of network traffic is illegal and unethical. Use responsibly on networks you own or have explicit permission to monitor.**

## Customization

- Number of packets captured: Modify the count parameter in the sniff() function.
- Payload display length: Adjust payload_display = payload.hex()[:100] to show more or fewer bytes.
- Protocol detection: Extend the protocols dictionary to include other IP protocols if needed.

## License

This project is released for educational purposes. No warranty is provided. Use at your own risk.

## Author
Developed by **DIAWARA Nana** .
