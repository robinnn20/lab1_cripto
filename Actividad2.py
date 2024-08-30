from scapy.all import *
import time

def send_icmp_message(target_ip, message):
    # Se define el tamaño total del campo de datos en bytes (48 bytes)
    data_length = 48
    
    for char in message:
        data = char + (' ' * (data_length - len(char)))
        # Crear el paquete ICMP con el campo de datos de longitud 48 bytes
        packet = IP(dst=target_ip)/ICMP()/data
        # Enviar el paquete
        send(packet, verbose=0)
        # Esperar un breve período para evitar generar demasiado tráfico
        time.sleep(0.1)
    
    print("Mensaje enviado con éxito.")

if __name__ == "__main__":
    target_ip = "192.168.1.1"
    message = input("Ingresa el mensaje a enviar: ")

    send_icmp_message(target_ip, message)
