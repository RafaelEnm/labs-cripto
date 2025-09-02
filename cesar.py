import sys

def cifrado_cesar(texto, desplazamiento):
  """
  Cifra un texto utilizando el algoritmo de César.

  Args:
    texto: El string a cifrar.
    desplazamiento: El número de posiciones a desplazar las letras.

  Returns:
    El texto cifrado.
  """
  texto_cifrado = ""
  for caracter in texto:
    if caracter.isalpha():
      # Mantiene el caso (mayúscula/minúscula) del caracter original
      codigo_ascii_inicio = ord('a') if caracter.islower() else ord('A')
      # Calcula la posición de la letra en el alfabeto (0-25)
      posicion = ord(caracter) - codigo_ascii_inicio
      # Aplica el desplazamiento y maneja el desborde del alfabeto
      nueva_posicion = (posicion + desplazamiento) % 26
      # Convierte la nueva posición de vuelta a un caracter
      texto_cifrado += chr(codigo_ascii_inicio + nueva_posicion)
    else:
      # Mantiene los caracteres que no son letras (números, espacios, etc.)
      texto_cifrado += caracter
  return texto_cifrado

if __name__ == "__main__":
  # Verifica si se proporcionaron los dos argumentos necesarios. [6]
  if len(sys.argv) != 3:
    print("Formato de uso: python3 cesar.py \"<texto a cifrar>\" <desplazamiento>")
    sys.exit(1)

  texto_original = sys.argv[1]
  try:
    desplazamiento = int(sys.argv[2])
  except ValueError:
    print("Error: El desplazamiento debe ser un número entero.")
    sys.exit(1)

  texto_cifrado = cifrado_cesar(texto_original, desplazamiento)
  print(f"Texto original: {texto_original}")
  print(f"Desplazamiento: {desplazamiento}")
  print(f"Texto cifrado: {texto_cifrado}")
