from scapy.all import *
import time

def send_icmp_message(target_ip, message):
    for char in message:
        # Crear el paquete ICMP con el carácter en el campo de datos
        packet = IP(dst=target_ip)/ICMP()/char
        # Enviar el paquete
        send(packet, verbose=0)
        # Esperar un breve período para evitar generar demasiado tráfico
        time.sleep(0.1)
    print("Mensaje enviado con éxito.")

if __name__ == "__main__":
    target_ip = "192.168.1.1"
    message = input("Ingresa el mensaje a enviar: ")

    send_icmp_message(target_ip, message)
