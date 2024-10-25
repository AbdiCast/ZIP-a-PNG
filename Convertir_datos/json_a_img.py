import os
import numpy as np
#import matplotlib.pyplot as plt
from PIL import Image

# Esta función se encarga de llevar un registro del los tamaños en bits de los archivos.
def agregar_numero_a_archivo(ruta_archivo, numero):
    try:
        # Abre el archivo en modo de escritura (append), para agregar contenido al final
        with open(ruta_archivo, 'a') as archivo:
            # Agrega el número en una nueva línea
            archivo.write(f"{numero}\n")
        print(f"Se ha agregado el número {numero} al archivo {ruta_archivo}.")
    except Exception as e:
        print(f"Ocurrió un error al intentar escribir en el archivo: {e}")

def guardar_imagen_con_pillow(ruta_img_completa, image_array):
    # Asegurarse de que el array tiene un rango de 0 a 255 y convertir a tipo uint8
    image_array = (image_array * 255).astype(np.uint8)
    
    # Crear una imagen de Pillow a partir del array de NumPy
    img = Image.fromarray(image_array)
    
    # Guardar la imagen en escala de grises (modo 'L')
    img.save(ruta_img_completa)

def json_a_img(ruta_json, ruta_img, width=128):
    try:
        # Abrimos y leemos el archivo json.
        with open(ruta_json, 'rb') as f:
            contenido = f.read()
        # Convertimos a un array de 8 bits (valores de 0 a 255)
        byte_array = np.frombuffer(contenido, dtype=np.uint8)

        # Guardamos el número de bytes en un archivo 
        ruta = "./Resultados/2 json/tam_bytes_arrays.txt"
        numero_a_agregar = byte_array.nbytes
        print(numero_a_agregar)
        agregar_numero_a_archivo(ruta, numero_a_agregar)

        # Calculamos la altura de la imagen
        height = len(byte_array) // width
        # Recortamos el byte_array si no es divisible por el ancho para evitar errores
        byte_array = byte_array[:height * width]
        # Redimensionar el vector de 1D a 2D (imagen en escala de grises)
        image = byte_array.reshape((height, width))

        # Mostramos la imagen
        #plt.imshow(image, cmap='gray')
        #plt.title("Malware json as Image")
        #plt.show()
        nombre_con_extension = os.path.split(ruta_json)[1]
        nombre_sin_extension = os.path.splitext(nombre_con_extension)[0]
        ruta_img_completa = os.path.join(ruta_img, nombre_sin_extension + '.png')
        # Guardar la imagen
        guardar_imagen_con_pillow(ruta_img_completa, image)
        #plt.imsave(ruta_img_completa, image, cmap='gray')
        
        print(f"Archivo img creado: '{ruta_img_completa}'.")
    
    except FileNotFoundError:
        print(f"Error: El archivo '{ruta_json}' no se encuentra.")
    except Exception as e:
        print(f"Ocurrió un error: {e}")
