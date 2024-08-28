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

# Función para determinar si una cadena es texto claro
def is_plaintext(message):
    alpha_count = sum(1 for c in message if c.isalpha())
    relevant_count = sum(1 for c in message if c.isalpha() or c.isspace() or c in '.,;:!?')
    return alpha_count / relevant_count > 0.7  # Umbral del 70% de letras alfabéticas

# Función para evaluar el texto y devolver la puntuación
def evaluar_texto(texto):
    alpha_count = sum(1 for c in texto if c.isalpha())
    relevant_count = sum(1 for c in texto if c.isalpha() or c.isspace() or c in '.,;:!?')
    puntuacion = alpha_count / relevant_count if relevant_count > 0 else 0
    return puntuacion

# Función para imprimir todas las combinaciones posibles y resaltar la más probable a ser texto claro
def print_possible_messages(message):
    mejores_mensajes = []
    mejor_puntuacion = 0

    for shift in range(26):
        decoded_message = decode_message(message, shift)
        puntuacion = evaluar_texto(decoded_message)
        if puntuacion > mejor_puntuacion:
            mejor_puntuacion = puntuacion
            mejores_mensajes = [(shift, decoded_message)]
        elif puntuacion == mejor_puntuacion:
            mejores_mensajes.append((shift, decoded_message))

    for shift, msg in mejores_mensajes:
        if is_plaintext(msg):
            print(colored(f"Shift {shift:2}: {msg}", 'green'))
        else:
            print(f"Shift {shift:2}: {msg}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    message = extract_message_from_icmp(pcap_file)
    print(f"\nOriginal Message: {message}")
    print("\nAll possible messages:")
    print_possible_messages(message)
