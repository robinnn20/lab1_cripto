import sys
from scapy.all import rdpcap, ICMP, IP
from termcolor import colored
import language_tool_python

# Definir un conjunto simple de palabras comunes para evaluar la legibilidad
COMMON_WORDS = {"the", "and", "is", "in", "of", "to", "a", "it", "with", "for", "on", "as", "at", "this", "that", "which", "or", "an"}

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
                ascii_data = raw_data.decode('ascii', errors='ignore').strip()  # Eliminar espacios en blanco
                messages.append(ascii_data)

    return ' '.join(messages)

# Función para verificar si el mensaje tiene un alto porcentaje de palabras comunes
def is_plaintext(message):
    words_in_message = message.lower().split()  # Separar en palabras por espacios
    if not words_in_message:  # Manejar caso de cadena vacía
        return False
    
    common_word_count = sum(1 for word in words_in_message if word in COMMON_WORDS)
    return common_word_count / len(words_in_message) > 0.3  # Umbral del 30%

# Función para evaluar el texto y calcular una puntuación
def evaluar_texto(texto):
    longitud = len(texto.split())
    errores = tool.check(texto)
    correcciones = len(errores)
    puntuacion = longitud - correcciones
    return puntuacion

# Función para encontrar el mensaje más claro
def encontrar_mensaje_claro(mensajes):
    puntuaciones = {mensaje: evaluar_texto(mensaje) for mensaje in mensajes}
    mensaje_claro = max(puntuaciones, key=puntuaciones.get)
    return mensaje_claro, puntuaciones[mensaje_claro]

# Función para imprimir todas las combinaciones posibles y resaltar las legibles
def print_possible_messages(message):
    mensajes_decodificados = []
    for shift in range(26):
        decoded_message = decode_message(message, shift)
        mensajes_decodificados.append(decoded_message)

    # Encontrar el mensaje más claro entre los decodificados
    mensaje_claro, puntuacion = encontrar_mensaje_claro(mensajes_decodificados)

    for shift, decoded_message in enumerate(mensajes_decodificados):
        if decoded_message == mensaje_claro:
            print(colored(f"Shift {shift:2}: {decoded_message}", 'green'))
        else:
            print(f"Shift {shift:2}: {decoded_message}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    message = extract_message_from_icmp(pcap_file)
    print(f"\nOriginal Message: {message}")
    print("\nAll possible messages:")
    print_possible_messages(message)
