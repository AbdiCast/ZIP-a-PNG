
# Para manipular archivos.
import glob
import os
import shutil

# Scripts para convertir de un tipo de dato a otro.
from Convertir_datos.unzip import unzip_with_7zip
from Convertir_datos.exe_a_bin import exe_a_bin
from Convertir_datos.bin_a_img import bin_a_img
from Convertir_datos.json_a_img import json_a_img

# Scripts para extrar características.
from Extraer_Caracteristicas.new_format_file import extraer_caractiscticas



# Esta función mueve un archivo dado a una ruta.
def mover_archivo(archivo, directorio_destino):
    # Comprobar si el archivo existe
    if os.path.isfile(archivo):
        # Mover el archivo al directorio de destino
        shutil.move(archivo, directorio_destino)

# Descomprimimos el .zip para obtener .exe
# Obtenemos la lista de rutas_zip
def obtener_archivosdeTipo(directorio, tipoArchivo):
    return glob.glob(os.path.join(directorio, tipoArchivo))
directorio = './Resultados/0 zipped/NoProcesados/'
rutas_zip = obtener_archivosdeTipo(directorio,'*.zip')
print(rutas_zip)
# Convertimos a imagen el contenido de cada zip
for ruta_zip in rutas_zip:
    try:
        # Descomprimimos el archivo y movemos a carpeta con unzip_with_7zip
        dir_destino = './Resultados/1 exe/' 
        password = 'infected' 
        unzip_with_7zip(ruta_zip, dir_destino, password)

        # Extraemos características de archivos en carpeta y creamos JSON con extraer_caractiscticas().
        directorio = './Resultados/1 exe/'
        ruta_json = './Resultados/2 json/'
        rutas_exe = obtener_archivosdeTipo(directorio,'*.exe')
        for ruta_exe in rutas_exe:
            nombre_con_extension = os.path.split(ruta_exe)[1]
            nombre_sin_extension = os.path.splitext(nombre_con_extension)[0]
            dest_file_path = f"{ruta_json}{nombre_sin_extension}.json"
            extraer_caractiscticas(ruta_exe,dest_file_path)

        # Convertimos de JSON a PNG.
        directorio = './Resultados/2 json/'
        ruta_img = './Resultados/3 img/'
        rutas_json = obtener_archivosdeTipo(directorio,'*.json')
        for ruta_json in rutas_json:
            json_a_img(ruta_json, ruta_img)

        # Finalmente movemos el zip ya procesado.
        archivo = ruta_zip  # Ruta del archivo a mover
        directorio_destino = './Resultados/0 zipped/Procesados'  # Directorio de destino
        mover_archivo(archivo, directorio_destino)
    except Exception as e:
        print(f"Se produjo un error con {ruta_zip}: {e}")