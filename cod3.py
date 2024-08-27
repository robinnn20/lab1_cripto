import sys
from scapy.all import rdpcap, ICMP, IP
from termcolor import colored
import re
import nltk

# Descarga del corpus de palabras en español
nltk.download('words')
words = set(nltk.corpus.words.words())

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

# Función para evaluar cuántas palabras reales contiene el mensaje decodificado
def count_real_words(decoded_message):
    words_in_message = re.findall(r'\b\w+\b', decoded_message)
    real_word_count = sum(1 for word in words_in_message if word.lower() in words)
    return real_word_count

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

# Función para imprimir todas las combinaciones posibles
def print_possible_messages(message):
    probable_message = ""
    max_real_words = 0

    for shift in range(26):
        decoded_message = decode_message(message, shift)
        real_word_count = count_real_words(decoded_message)
        print(f"Shift {shift:2}: {decoded_message} (Real words: {real_word_count})")
        
        if real_word_count > max_real_words:
            max_real_words = real_word_count
            probable_message = decoded_message

    return probable_message

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    message = extract_message_from_icmp(pcap_file)
    print(f"\nOriginal Message: {message}")
    print("\nAll possible messages:")
    probable_message = print_possible_messages(message)

    print(colored(f"\nMost probable message: {probable_message}", 'green'))
