import subprocess
import os
import shutil
# Esta función ayuda a extrar los .exe de la ruta_carpeta descomprimida original.
def mover_archivos_exe(ruta_carpeta):
    # Verificar si la ruta_carpeta existe
    if not os.path.exists(ruta_carpeta):
        print(f"La ruta_carpeta al sacar .exe de su carpeta unzipped {ruta_carpeta} no existe.")
        return
    # Obtener el directorio padre
    directorio_padre = os.path.dirname(ruta_carpeta)
    # Listar los archivos en la ruta_carpeta
    archivos = os.listdir(ruta_carpeta)
    # Mover archivos .exe al directorio padre
    for archivo in archivos:
        if archivo.endswith('.exe'):
            ruta_archivo = os.path.join(ruta_carpeta, archivo)
            shutil.move(ruta_archivo, directorio_padre)  # Mover al directorio padre
    # Intentar eliminar la ruta_carpeta
    os.rmdir(ruta_carpeta)

# Obtenemos los nombres de carpetas en un directorio dado.
def obtener_rutas_carpetas(directorio):
    # Lista para almacenar las rutas de las carpetas
    rutas_carpetas = []
    # Verificar si el directorio existe
    if not os.path.exists(directorio):
        print(f"El directorio {directorio} no existe.")
        return rutas_carpetas
    # Listar los elementos en el directorio
    for elemento in os.listdir(directorio):
        ruta_elemento = os.path.join(directorio, elemento)
        # Verificar si es una carpeta
        if os.path.isdir(ruta_elemento):
            rutas_carpetas.append(ruta_elemento)  # Añadir la ruta de la carpeta a la lista
    return rutas_carpetas

def unzip_with_7zip(zip_file_path, output_dir, password):
    try:
        # Cambiar esta ruta si es necesario
        seven_zip_path = r'C:/Program Files/7-Zip/7z.exe'
        # Comando 7z para descomprimir con contraseña
        command = [seven_zip_path, 'x', f'-p{password}', zip_file_path, f'-o{output_dir}']
        # Ejecutar el comando
        result = subprocess.run(command, capture_output=True, text=True)
        # Verificar si hubo un error en la salida
        if result.returncode == 0:
            print(f"Archivo descomprimido con éxito : {output_dir}")
            # Obtenemos las carpetas en pasadas a la ruta destino.
            carpetas_unzipped = obtener_rutas_carpetas('./Resultados/1 exe/')
            for carpeta_unzipped in carpetas_unzipped:
                # aquí movemos la carpeta descomprimida y la sacamos de su directorio padre.
                mover_archivos_exe(carpeta_unzipped)
        else:
            print(f"Error al descomprimir el archivo: {result.stderr}")
    
    except Exception as e:
        print(f"Se produjo un error: {e}")
