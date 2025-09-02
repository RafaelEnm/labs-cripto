import sys
from collections import defaultdict
from scapy.all import rdpcap, ICMP, IP
from colorama import init, Fore, Style

# Inicializa colorama para que funcione en todas las terminales
init()

# --- Diccionario de Palabras en Español ---
# Para un programa real, se usaría un archivo de diccionario mucho más grande.
# Esta lista simple sirve para identificar el texto más probable.
DICCIONARIO_ESPANOL = {
    "hola", "mundo", "este", "es", "un", "mensaje", "secreto", "prueba", "datos",
    "informacion", "exfiltracion", "ayuda", "socorro", "urgente", "clave",
    "contrasena", "el", "la", "los", "las", "de", "que", "y", "a", "en", "como",
    "con", "para", "por", "si", "no", "pero", "mas", "mi", "me", "te", "se", "lo"
}

def descifrado_cesar(texto_cifrado, desplazamiento):
    """Descifra un texto utilizando el algoritmo de César."""
    texto_claro = ""
    for caracter in texto_cifrado:
        if caracter.isalpha():
            codigo_ascii_inicio = ord('a') if caracter.islower() else ord('A')
            posicion = ord(caracter) - codigo_ascii_inicio
            # La operación clave es la resta en lugar de la suma
            nueva_posicion = (posicion - desplazamiento) % 26
            texto_claro += chr(codigo_ascii_inicio + nueva_posicion)
        else:
            texto_claro += caracter
    return texto_claro

def calcular_puntaje_idioma(texto, diccionario):
    """
    Calcula un puntaje basado en cuántas palabras del texto están en el diccionario.
    Un puntaje más alto significa que es más probable que sea un texto en claro.
    """
    puntaje = 0
    palabras = texto.lower().split()
    if not palabras:
        return 0
        
    for palabra in palabras:
        # Elimina puntuación simple para una mejor coincidencia
        palabra_limpia = ''.join(c for c in palabra if c.isalpha())
        if palabra_limpia in diccionario:
            puntaje += 1
            
    # Se normaliza el puntaje por la cantidad de palabras para no favorecer textos largos
    return puntaje / len(palabras)


def main(archivo_pcap):
    """
    Función principal que lee el pcap, extrae y descifra los mensajes.
    """
    print(f"[*] Analizando el archivo: {archivo_pcap}")
    
    try:
        paquetes_pcap = rdpcap(archivo_pcap)
    except Exception as e:
        print(f"{Fore.RED}[!] Error al leer el archivo pcap: {e}{Style.RESET_ALL}")
        return

    # Usamos un defaultdict para agrupar paquetes por sesión
    # Una sesión se define por (ip_origen, ip_destino, icmp_id)
    sesiones = defaultdict(list)

    print("[*] Filtrando paquetes ICMP echo-request (tipo 8)...")
    for paquete in paquetes_pcap:
        if paquete.haslayer(ICMP) and paquete[ICMP].type == 8:
            # Aseguramos que el paquete tenga también capa IP
            if paquete.haslayer(IP):
                llave_sesion = (paquete[IP].src, paquete[IP].dst, paquete[ICMP].id)
                sesiones[llave_sesion].append(paquete)

    if not sesiones:
        print(f"{Fore.YELLOW}[!] No se encontraron sesiones de ICMP echo-request en el archivo.{Style.RESET_ALL}")
        return

    print(f"[*] Se encontraron {len(sesiones)} posibles sesiones ICMP para analizar.\n")

    # Analizar cada sesión encontrada
    for i, (llave, paquetes_sesion) in enumerate(sesiones.items()):
        ip_origen, ip_destino, icmp_id = llave
        
        print(f"--- Analizando Sesión #{i+1}: {ip_origen} -> {ip_destino} (ID: {icmp_id}) ---")

        # Ordenar los paquetes por su número de secuencia para reconstruir el mensaje
        paquetes_sesion.sort(key=lambda p: p[ICMP].seq)
        
        mensaje_cifrado = ""
        for paquete in paquetes_sesion:
            try:
                # Extraemos el caracter oculto del 9º byte del payload (índice 8)
                payload = paquete[ICMP].load
                if len(payload) >= 9:
                    caracter_oculto = chr(payload[8])
                    mensaje_cifrado += caracter_oculto
            except (IndexError, TypeError):
                # Ignoramos paquetes que no tengan el payload esperado
                continue
        
        if not mensaje_cifrado:
            print(f"{Fore.YELLOW}  [!] No se pudo extraer un mensaje de esta sesión.{Style.RESET_ALL}\n")
            continue
            
        print(f"  [+] Mensaje cifrado extraído: '{mensaje_cifrado}'")
        
        mejor_mensaje = ""
        mejor_desplazamiento = 0
        max_puntaje = -1

        print("  [*] Probando todos los desplazamientos posibles (1-25):")
        # Brute-force del cifrado César
        for desplazamiento in range(1, 26):
            mensaje_claro = descifrado_cesar(mensaje_cifrado, desplazamiento)
            puntaje = calcular_puntaje_idioma(mensaje_claro, DICCIONARIO_ESPANOL)
            
            print(f"    - Desplazamiento {desplazamiento:2d}: {mensaje_claro}")

            if puntaje > max_puntaje:
                max_puntaje = puntaje
                mejor_mensaje = mensaje_claro
                mejor_desplazamiento = desplazamiento
        
        print("\n  [>] Resultado más probable para esta sesión:")
        if max_puntaje > 0:
            print(f"    Desplazamiento: {mejor_desplazamiento}")
            print(f"    Mensaje: {Fore.GREEN}{Style.BRIGHT}{mejor_mensaje}{Style.RESET_ALL}\n")
        else:
            print(f"    {Fore.YELLOW}No se encontró una coincidencia clara con el diccionario.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Formato de uso: python3 mitm.py <ruta_del_archivo.pcapng>")
        sys.exit(1)
        
    archivo_pcap = sys.argv[1]
    main(archivo_pcap)
