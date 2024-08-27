import sys
from scapy.all import rdpcap, ICMP, IP
from termcolor import colored
import string

# Función para decodificar el mensaje
def decode_message(data, shift):
    decoded = []
    for char in data:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            decoded.append(chr((ord(char) - offset + shift) % 26 + offset))
        else:
            decoded.append(char)
    return ''.join(decoded)

# Función para extraer el mensaje de los paquetes ICMP que coinciden con los criterios
def extract_message_from_icmp(pcap_file):
    packets = rdpcap(pcap_file)
    messages = []

    for packet in packets:
        if packet.haslayer(ICMP):
            if packet[IP].src == "192.168.1.1" and packet[IP].dst == "10.0.2.15" and packet[ICMP].type == 0:  # Echo Reply
                raw_data = bytes(packet[ICMP].payload)
                ascii_data = raw_data.decode('ascii', errors='ignore')
                messages.append(ascii_data)

    return ' '.join(messages)

# Función para determinar si una cadena es probablemente texto claro
def is_probable_text(message):
    allowed_chars = string.ascii_letters + string.digits + string.punctuation + ' '
    return all(char in allowed_chars for char in message)

# Función para determinar el mensaje más probable
def find_most_probable_message(message):
    probable_message = None

    for shift in range(26):
        decoded_message = decode_message(message, shift)
        if is_probable_text(decoded_message):
            probable_message = decoded_message
            break

    return probable_message

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    message = extract_message_from_icmp(pcap_file)
    
    probable_message = find_most_probable_message(message)
    
    if probable_message:
        print(colored(f"\nMost probable message: {probable_message}", 'green'))
    else:
        print("No probable clear text message found.")
