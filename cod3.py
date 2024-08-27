import scapy.all as scapy
import sys
import colorama
from colorama import Fore, Style

colorama.init()

TARGET_MESSAGE = "criptografia y seguridad en redes"

def decode_message(data, shift):
    return ''.join(chr((byte - shift) % 256) for byte in data)

def calculate_similarity(decoded_message):
    # Calcula una medida simple de similitud con el mensaje objetivo
    # Contar coincidencias de caracteres en las posiciones correspondientes
    target_len = len(TARGET_MESSAGE)
    similarity_score = 0
    for i in range(min(target_len, len(decoded_message))):
        if decoded_message[i] == TARGET_MESSAGE[i]:
            similarity_score += 1
    return similarity_score

def main(pcap_file):
    # Cargar los paquetes ICMP del archivo
    packets = scapy.rdpcap(pcap_file)
    
    # Filtrar solo los paquetes ICMP
    icmp_packets = [pkt for pkt in packets if scapy.ICMP in pkt]
    
    # Extraer los datos de los paquetes ICMP
    icmp_data = b''.join(bytes(pkt[scapy.Raw].load) for pkt in icmp_packets if scapy.Raw in pkt)
    
    best_message = None
    best_score = -1
    best_shift = None
    
    # Generar todas las combinaciones posibles de corrimientos (1-255)
    for shift in range(1, 256):
        decoded_message = decode_message(icmp_data, shift)
        score = calculate_similarity(decoded_message)
        
        print(f"Shift {shift}: {decoded_message}")

        if score > best_score:
            best_score = score
            best_message = decoded_message
            best_shift = shift
    
    if best_message:
        print(Fore.GREEN + f"Probable mensaje: {best_message} (Shift {best_shift})" + Style.RESET_ALL)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 tu_script.py archivo.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]
    main(pcap_file)
