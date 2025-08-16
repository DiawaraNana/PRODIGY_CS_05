from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

protocols = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    50: "ESP",
    51: "AH",
    89: "OSPF"
}

def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        length = len(packet)
        
        proto = ""
        details = ""
        
        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            details = f"{ip_src}:{sport} -> {ip_dst}:{dport}"
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            details = f"{ip_src}:{sport} -> {ip_dst}:{dport}"
        elif ICMP in packet:
            proto = "ICMP"
            icmp_type = packet[ICMP].type
            details = f"{ip_src} -> {ip_dst} Type: {icmp_type}"
        else:
            proto_num = packet[IP].proto
            if proto_num in protocols:
                 proto = protocols[proto_num]
            else:
                 proto = f"Other Proto ({proto_num})"
            details = f"{ip_src} -> {ip_dst}"
        
       
        payload = bytes(packet[IP].payload)
        payload_display = payload.hex()[:100]  
        
        print(f"\n[{timestamp}] {proto} Packet: {details} | Length: {length} bytes | Payload (hex): {payload_display}")


sniff(iface="eth0", prn=packet_callback, count=60, store=False)

