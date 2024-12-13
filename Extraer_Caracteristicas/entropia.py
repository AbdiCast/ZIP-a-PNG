import math

def calculate_entropy(data):
    """Calcula la entropía de un bloque de datos."""
    if not data:
        return 0
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    entropy = 0.0
    for count in frequency:
        if count > 0:
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
    return round(entropy, 5)

def calculate_file_entropy(file_path):
    with open(file_path, 'rb') as f:
        datos = f.read()

    # Frecuencia de cada byte (256 posibles valores)
    frecuencias = [0] * 256
    for byte in datos:
        frecuencias[byte] += 1

    # Total de bytes en el archivo
    total_bytes = len(datos)

    # Calcular la entropía 
    entropia = 0.0
    for frecuencia in frecuencias:
        if frecuencia > 0:
            probabilidad = frecuencia / total_bytes
            entropia -= probabilidad * math.log2(probabilidad)

    return round(entropia, 5)

if __name__ == "__main__":
    # Ejemplo de uso
    ruta_archivo = './7z2408-x64.exe'
    entropia = calcular_entropia(ruta_archivo)
    print(f'La entropía del archivo es: {entropia}')