import sys
from scapy.all import rdpcap, ICMP, IP
from termcolor import colored

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
    for shift in range(26):
        decoded_message = decode_message(message, shift)
        print(f"Shift {shift:2}: {decoded_message}")

# Función para determinar si una cadena es de texto claro
def is_probable_plaintext(decoded_message):
    # Puedes ajustar el criterio según lo que consideres como texto claro.
    # Por ejemplo, aquí consideramos texto claro si tiene más del 70% de letras (y no solo símbolos).
    letter_count = sum(c.isalpha() for c in decoded_message)
    return letter_count / len(decoded_message) > 0.7

# Función para destacar el mensaje más probable y colorear el texto claro
def highlight_most_probable_message(message):
    for shift in range(26):
        decoded_message = decode_message(message, shift)
        if is_probable_plaintext(decoded_message):
            print(colored(f"\nProbable plaintext message (Shift {shift}): {decoded_message}", 'green'))
            return
    print("\nNo probable plaintext message found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    message = extract_message_from_icmp(pcap_file)
    print(f"\nOriginal Message: {message}")
    print("\nAll possible messages:")
    print_possible_messages(message)
    highlight_most_probable_message(message)
