from scapy.all import rdpcap, ICMP, IP
from termcolor import colored

# Función para descifrar el mensaje utilizando un cifrado César
def descifrar_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = ord('a') if caracter.islower() else ord('A')
            resultado += chr((ord(caracter) - base + desplazamiento) % 26 + base)
        else:
            resultado += caracter
    return resultado

# Función para analizar la captura y extraer los mensajes ICMP reply específicos
def extraer_icmp_reply(captura):
    mensajes = []
    paquetes = rdpcap(captura)
    for paquete in paquetes:
        if ICMP in paquete and paquete[ICMP].type == 0:  # ICMP type 0 es reply
            if paquete[IP].src == '192.168.1.1' and paquete[IP].dst == '10.0.2.15':
                icmp_carga = bytes(paquete[ICMP].payload)
                try:
                    mensaje = icmp_carga.decode('utf-8')
                    mensajes.append(mensaje)
                except UnicodeDecodeError:
                    continue
    return mensajes

# Función para determinar si un texto es en claro
def es_mensaje_claro(texto):
    palabras_comunes = ['the', 'and', 'el', 'la', 'es', 'en']
    for palabra in palabras_comunes:
        if palabra in texto.lower():
            return True
    return False

# Función principal para ejecutar el análisis
def analizar_captura(captura):
    mensajes = extraer_icmp_reply(captura)
    for mensaje in mensajes:
        print(f"Mensaje encontrado: {mensaje}")
        opciones_descifradas = []
        for desplazamiento in range(26):
            descifrado = descifrar_cesar(mensaje, desplazamiento)
            opciones_descifradas.append(descifrado)
            if es_mensaje_claro(descifrado):
                print(colored(f"Posible mensaje en claro (desplazamiento {desplazamiento}): {descifrado}", 'green'))
            else:
                print(f"Desplazamiento {desplazamiento}: {descifrado}")
        print("\n")

# Ruta del archivo de captura
captura = "/home/robin/Escritorio/lab1cripto.pcapng"  # Actualiza con la ruta correcta

# Ejecutar el análisis
analizar_captura(captura)
