from scapy.all import *
import time

def send_icmp_message(target_ip, message):
    data_length = 48  # Tamaño total del campo de datos en bytes
    packet_id = random.randint(0, 65535)  # Generar un ID de paquete ICMP aleatorio
    seq_number = 0  # Número de secuencia inicial
    
    for char in message:
        # Crear el contenido del campo de datos con el carácter y rellenar el resto con espacios
        data = char + (' ' * (data_length - len(char)))
        
        # Crear el paquete ICMP con el ID y número de secuencia específicos
        packet = IP(dst=target_ip)/ICMP(id=packet_id, seq=seq_number)/data
        
        # Enviar el paquete
        send(packet, verbose=0)
        
        # Incrementar el número de secuencia para el próximo paquete
        seq_number += 1
        
        # Esperar un breve período para evitar generar demasiado tráfico
        time.sleep(0.1)
    
    print("Mensaje enviado con éxito.")

if __name__ == "__main__":
    # Solicitar la IP de destino y el mensaje al usuario
    target_ip = input("Ingresa la IP de destino: ")
    message = input("Ingresa el mensaje a enviar: ")

    send_icmp_message(target_ip, message)
