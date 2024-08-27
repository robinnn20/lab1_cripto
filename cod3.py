import sys
from scapy.all import rdpcap, ICMP, IP
from termcolor import colored

TARGET_PHRASE = "criptografia y seguridad en redes"

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

# Función para imprimir todas las combinaciones posibles
def print_possible_messages(message):
    best_shift = 0
    highest_similarity = 0
    for shift in range(26):
        decoded_message = decode_message(message, shift)
        similarity = sum(1 for a, b in zip(decoded_message, TARGET_PHRASE) if a == b)
        print(f"Shift {shift:2}: {decoded_message}")
        if similarity > highest_similarity:
            highest_similarity = similarity
            best_shift = shift

    return best_shift

# Función para destacar el mensaje más probable
def highlight_most_probable_message(message, best_shift):
    probable_message = decode_message(message, best_shift)
    print(colored(f"\nMost probable message (Shift {best_shift}): {probable_message}", 'green'))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    message = extract_message_from_icmp(pcap_file)
    print(f"\nOriginal Message: {message}")
    print("\nAll possible messages:")
    best_shift = print_possible_messages(message)
    highlight_most_probable_message(message, best_shift)
