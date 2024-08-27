import sys
from scapy.all import rdpcap, ICMP
from termcolor import colored

# Función para decodificar el payload de ICMP con un desplazamiento dado
def decode_message(payloads, shift):
    # Decodificar cada payload como una letra usando el desplazamiento dado
    decoded = ''.join(chr((payload[0] + shift) % 256) for payload in payloads)
    return decoded

# Función para determinar si una cadena es probable que sea texto en claro
def is_likely_plaintext(text):
    common_words = ['the', 'and', 'is', 'in', 'to', 'it', 'of', 'you', 'that', 'a', 'i']
    return any(word in text.lower() for word in common_words)

def main():
    # Verificar si se proporcionó el archivo .pcapng
    if len(sys.argv) != 2:
        print("Uso: python3 decode_icmp.py archivo.pcapng")
        sys.exit(1)

    pcap_file = sys.argv[1]

    # Leer el archivo .pcapng
    packets = rdpcap(pcap_file)

    # Extraer el primer byte del payload de los paquetes ICMP de respuesta
    icmp_payloads = []
    for packet in packets:
        if (ICMP in packet and packet[ICMP].type == 0 and  # ICMP Echo Reply
            packet.src == '192.168.1.1' and packet.dst == '10.0.2.15'):
            icmp_payloads.append(packet[ICMP].load)

    # Probar todos los desplazamientos posibles (0-255)
    for shift in range(256):
        decoded_message = decode_message(icmp_payloads, shift)
        if is_likely_plaintext(decoded_message):
            print(colored(f'Decoded with shift {shift}: {decoded_message}', 'green'))
        else:
            print(f'Decoded with shift {shift}: {decoded_message}')

if __name__ == "__main__":
    main()
