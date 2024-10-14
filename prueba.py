import os
import glob
def obtener_archivosdeTipo(directorio, tipoArchivo):
    return glob.glob(os.path.join(directorio, tipoArchivo))
directorio = './0 zipped/NoProcesados/'
rutas_zip = obtener_archivosdeTipo(directorio,'*.zip')
print(rutas_zip)