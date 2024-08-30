from scapy.all import *
import time

def send_icmp_message(target_ip, message):
    data_length = 48  # Tamaño total del campo de datos en bytes
    packet_id = 0  
    seq_number = 0  # Número de secuencia inicial
    for char in message:
        data = char + (' ' * (data_length - len(char))) 
        # Se crea el paquete ICMP con el ID y número de secuencia específicos
        packet = IP(dst=target_ip)/ICMP(id=packet_id, seq=seq_number)/data  
        # Enviar el paquete
        send(packet, verbose=0) 
        # Incrementar el número de secuencia para el próximo paquete
        seq_number += 1
        packet_id += 1
        # Esperar un breve período para evitar generar demasiado tráfico
        time.sleep(0.1)
    
    print("Mensaje enviado con éxito.")

if __name__ == "__main__":
    # Solicitar la IP de destino y el mensaje al usuario
    target_ip = "192.168.1.1"
    message = input("Ingresa el mensaje a enviar: ")

    send_icmp_message(target_ip, message)
