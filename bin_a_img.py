import os
import numpy as np
import matplotlib.pyplot as plt

def bin_a_img(ruta_bin, ruta_img, width=128):
    try:
        # Abrimos y leemos el archivo binario.
        with open(ruta_bin, 'rb') as f:
            contenido = f.read()
        # Convertimos a un array de 8 bits (valores de 0 a 255)
        byte_array = np.frombuffer(contenido, dtype=np.uint8)

        # Calculamos la altura de la imagen
        height = len(byte_array) // width
        # Recortamos el byte_array si no es divisible por el ancho para evitar errores
        byte_array = byte_array[:height * width]
        # Redimensionar el vector de 1D a 2D (imagen en escala de grises)
        image = byte_array.reshape((height, width))

        # Mostramos la imagen
        #plt.imshow(image, cmap='gray')
        #plt.title("Malware Binary as Image")
        #plt.show()
        nombre_con_extension = os.path.split(ruta_bin)[1]
        nombre_sin_extension = os.path.splitext(nombre_con_extension)[0]
        ruta_img_completa = os.path.join(ruta_img, nombre_sin_extension + '.png')
        # Guardar la imagen
        plt.imsave(ruta_img_completa, image, cmap='gray')
        
        print(f"Archivo img creado: '{ruta_img_completa}'.")
    
    except FileNotFoundError:
        print(f"Error: El archivo '{ruta_bin}' no se encuentra.")
    except Exception as e:
        print(f"Ocurrió un error: {e}")
