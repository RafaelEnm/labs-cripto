# labs-cripto
Canal Encubierto ICMP con Cifrado César:
Prueba de concepto de un canal encubierto de datos que utiliza paquetes ICMP (ping) para enviar un mensaje cifrado con el algoritmo César.

Qué Hacen los Scripts:
cesar.py: Cifra un mensaje. Recibe un string y un desplazamiento y devuelve el texto .
icmp.py: Envía el texto cifrado. Oculta cada caracter en el payload de un paquete ICMP de apariencia normal y lo envía a un destino fijo.
mitm.py: Recibe un archivo de captura de red (.pcapng), extrae el mensaje oculto de los paquetes ICMP y prueba todos los desplazamientos posibles para encontrar el texto original.

Cómo Utilizar:
1. Configurar IP de destino en icmp.py: Modifica la variable IP_DESTINO_FIJA con la IP de la máquina que recibirá los paquetes (por default esta puesta 8.8.8.8, la IP de google).
2. Cifrar el mensaje con cesar.py
3. Iniciar Captura de Red (Máquina Destino): Usa tcpdump o Wireshark para capturar el tráfico ICMP y guardarlo.
4. Enviar Mensaje Oculto (Máquina Origen): Ejecuta el script mitm.py. Se requieren privilegios. El script mostrará todas las combinaciones y resaltará en verde la más probable.
  
