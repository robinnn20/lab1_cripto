from scapy.all import rdpcap, ICMP
from termcolor import colored

# Función para decodificar el payload de ICMP con un desplazamiento dado
def decode_message(payload, shift):
    decoded = ''.join(chr((byte + shift) % 256) for byte in payload)
    return decoded

# Función para determinar si una cadena es probable que sea texto en claro
def is_likely_plaintext(text):
    # Esto es una simplificación, se puede mejorar con análisis más sofisticado.
    common_words = ['the', 'and', 'is', 'in', 'to', 'it', 'of', 'you', 'that', 'a', 'i']
    return any(word in text.lower() for word in common_words)

# Leer el archivo .pcap
packets = rdpcap('captura.pcap')

# Extraer los payloads de los paquetes ICMP
icmp_payloads = []
for packet in packets:
    if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
        icmp_payloads.append(bytes(packet[ICMP].payload))

# Unir todos los payloads en una sola secuencia
message = b''.join(icmp_payloads)

# Probar todos los desplazamientos posibles (0-255)
for shift in range(256):
    decoded_message = decode_message(message, shift)
    if is_likely_plaintext(decoded_message):
        print(colored(f'Decoded with shift {shift}: {decoded_message}', 'green'))
    else:
        print(f'Decoded with shift {shift}: {decoded_message}')
