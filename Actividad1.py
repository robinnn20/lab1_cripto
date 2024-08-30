def cifrado_cesar(texto, corrimiento):
    resultado = ""
   
    # Asegurarse de que el corrimiento esté dentro de los límites de 0-25
    corrimiento = corrimiento % 26

    for letra in texto:
        # Cifrado para letras mayúsculas
        if letra.isupper():
            resultado += chr((ord(letra) - ord('A') + corrimiento) % 26 + ord('A'))
        # Cifrado para letras minúsculas
        elif letra.islower():
            resultado += chr((ord(letra) - ord('a') + corrimiento) % 26 + ord('a'))
        # Si no es letra, se deja igual
        else:
            resultado += letra

    return resultado

# Ejemplo de uso:
texto_a_cifrar = input("Ingrese el texto a cifrar: ")
corrimiento = int(input("Ingrese el corrimiento: "))

texto_cifrado = cifrado_cesar(texto_a_cifrar, corrimiento)
print("Texto cifrado:", texto_cifrado)
