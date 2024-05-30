pip install scapy
from scapy.all import sniff, IP, TCP, UDP
import logging

# Setup logging
logging.basicConfig(filename="intrusion_detection.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Define suspicious patterns
SUSPICIOUS_PATTERNS = {
    'SYN_FLOOD': {'count': 0, 'threshold': 100, 'message': 'Possible SYN flood detected from IP: {}'},
    'PORT_SCAN': {'count': 0, 'threshold': 10, 'message': 'Possible port scan detected from IP: {}'}
}

# Callback function to process packets
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        
        # Check for SYN flood (many SYN packets from the same IP)
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            src_ip = ip_layer.src
            SUSPICIOUS_PATTERNS['SYN_FLOOD']['count'] += 1
            if SUSPICIOUS_PATTERNS['SYN_FLOOD']['count'] > SUSPICIOUS_PATTERNS['SYN_FLOOD']['threshold']:
                logging.warning(SUSPICIOUS_PATTERNS['SYN_FLOOD']['message'].format(src_ip))
                print(SUSPICIOUS_PATTERNS['SYN_FLOOD']['message'].format(src_ip))
                SUSPICIOUS_PATTERNS['SYN_FLOOD']['count'] = 0  # Reset counter after logging

        # Check for port scan (many different ports targeted from the same IP)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            src_ip = ip_layer.src
            SUSPICIOUS_PATTERNS['PORT_SCAN']['count'] += 1
            if SUSPICIOUS_PATTERNS['PORT_SCAN']['count'] > SUSPICIOUS_PATTERNS['PORT_SCAN']['threshold']:
                logging.warning(SUSPICIOUS_PATTERNS['PORT_SCAN']['message'].format(src_ip))
                print(SUSPICIOUS_PATTERNS['PORT_SCAN']['message'].format(src_ip))
                SUSPICIOUS_PATTERNS['PORT_SCAN']['count'] = 0  # Reset counter after logging

# Start sniffing packets (you might need to run this script with sudo)
print("Starting network-based Intrusion Detection System...")
sniff(prn=packet_callback, store=0)

sudo python3 intrusion_detection.py