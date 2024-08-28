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

# Función para evaluar la calidad de un texto
def evaluar_texto(texto):
    longitud = len(texto.split())
    errores = sum(1 for c in texto if not c.isalpha() and not c.isspace() and c not in '.,;:!?')
    puntuacion = longitud - errores
    return puntuacion

# Función para encontrar el mensaje más claro
def encontrar_mensaje_claro(messages):
    mejor_mensaje = None
    mejor_puntuacion = float('-inf')

    for message in messages:
        puntuacion = evaluar_texto(message)
        if puntuacion > mejor_puntuacion:
            mejor_puntuacion = puntuacion
            mejor_mensaje = message

    return mejor_mensaje, mejor_puntuacion

# Función para imprimir todas las combinaciones posibles y resaltar la más clara
def print_possible_messages(message):
    mensajes_decodificados = []
    for shift in range(26):
        decoded_message = decode_message(message, shift)
        mensajes_decodificados.append(decoded_message)

    mejor_mensaje, puntuacion = encontrar_mensaje_claro(mensajes_decodificados)
    if mejor_mensaje:
        print(colored(f"El mensaje más claro es: {mejor_mensaje} con una puntuación de {puntuacion}.", 'green'))
    else:
        print("No se encontró un mensaje claro.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    message = extract_message_from_icmp(pcap_file)
    print(f"\nMensaje original: {message}")
    print("\nTodos los mensajes posibles:")
    print_possible_messages(message)
