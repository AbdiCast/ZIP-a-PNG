
# Para manipular archivos.
import glob
import os
import shutil

# Scripts para convertir de un tipo de dato a otro.
from Convertir_datos.unzip import unzip_with_7zip
from Convertir_datos.exe_a_bin import exe_a_bin
from Convertir_datos.bin_a_img import bin_a_img

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
directorio = './0 zipped/NoProcesados/'
rutas_zip = obtener_archivosdeTipo(directorio,'*.zip')
print(rutas_zip)
# Convertimos a imagen el contenido de cada zip
for ruta_zip in rutas_zip:
    try:
        # Descomprimimos el archivo.
        dir_destino = './1 exe/' 
        password = 'infected' 
        unzip_with_7zip(ruta_zip, dir_destino, password)

        # Procesado de PESTUDIO...

        # Convertir datos a JSON...

        # Convertimos de .exe a .bin
        directorio = './1 exe/'
        ruta_bin = './2 bin/'
        rutas_exe = obtener_archivosdeTipo(directorio,'*.exe')
        for ruta_exe in rutas_exe:
            exe_a_bin(ruta_exe, ruta_bin)
        # Convertimos de JSON a PNG...
        # Convertimos de .bin a imagen
        directorio = './2 bin/'
        ruta_img = './3 img/'
        rutas_bin = obtener_archivosdeTipo(directorio,'*.bin')
        for ruta_bin in rutas_bin:
            bin_a_img(ruta_bin, ruta_img)

        # Finalmente movemos el zip ya procesado.
        archivo = ruta_zip  # Ruta del archivo a mover
        directorio_destino = './0 zipped/Procesados'  # Directorio de destino
        mover_archivo(archivo, directorio_destino)
    except Exception as e:
        print(f"Se produjo un error con {ruta_zip}: {e}")