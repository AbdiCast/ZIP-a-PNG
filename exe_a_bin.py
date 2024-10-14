import os

# Convierte un archivo exe a bin.
def exe_a_bin(ruta_exe, ruta_bin):
    try:
        # Abrimos el archivo exe como binario.
        with open(ruta_exe, 'rb') as exe_file:  
            # Leemos el archivo exe.
            contenido_bin = exe_file.read()  
        
        # Creamos un binario.
        nombre_con_extension = os.path.split(ruta_exe)[1]
        nombre_sin_extension = os.path.splitext(nombre_con_extension)[0]
        ruta_bin_completa = os.path.join(ruta_bin, nombre_sin_extension + '.bin')
        with open(ruta_bin_completa, 'wb') as archivo_bin:
            # Escribimos el conenido
            archivo_bin.write(contenido_bin)
        # Mostramos éxito.
        print(f"Archivo binario creado: '{ruta_bin}'.")
    
    except FileNotFoundError:
        print(f"Error: El archivo '{ruta_exe}' no se encuentra.")
    except Exception as e:
        print(f"Ocurrió un error: {e}")


