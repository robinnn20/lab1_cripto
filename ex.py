import sys
from scapy.all import rdpcap, ICMP, IP
from termcolor import colored
import language_tool_python

# Inicializar el verificador de gramática
tool = language_tool_python.LanguageTool('es')

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

    return messages

# Función para evaluar el texto y determinar su claridad
def evaluar_texto(texto):
    longitud = len(texto.split())
    errores = tool.check(texto)
    correcciones = len(errores)
    puntuacion = longitud - correcciones
    return puntuacion

# Función para imprimir todas las combinaciones posibles
def print_possible_messages(message):
    for shift in range(26):
        decoded_message = decode_message(message, shift)
        print(f"Shift {shift:2}: {decoded_message}")

# Función para determinar y resaltar el mensaje más probable
def highlight_most_probable_message(messages):
    mejor_mensaje = ""
    mejor_puntuacion = float('-inf')

    for message in messages:
        for shift in range(26):
            decoded_message = decode_message(message, shift)
            puntuacion = evaluar_texto(decoded_message)

            if puntuacion > mejor_puntuacion:
                mejor_puntuacion = puntuacion
                mejor_mensaje = decoded_message

    print(colored(f"\nMost probable message: {mejor_mensaje}", 'green'))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    messages = extract_message_from_icmp(pcap_file)

    print("\nExtracted Messages:")
    for msg in messages:
        print(f"- {msg}")

    print("\nAll possible messages:")
    for msg in messages:
        print_possible_messages(msg)

    highlight_most_probable_message(messages)
