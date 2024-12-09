import xml.etree.ElementTree as ET
import r2pipe
import json

def process_xml(file_path, imports):

    # Usamos iterparse para leer el XML de manera incremental
    context = ET.iterparse(file_path, events=("start", "end"))
    
    matches = {}
    for event, elem in context:
        if event == "start" and elem.tag == "lib":

            # Procesamos los atributos del elemento <lib>
            name = elem.attrib.get("name")
            flag = elem.attrib.get("flag")
            desc = elem.attrib.get("desc")
            
            # Buscar los elementos <fcts> y sus subelementos <fct>
            fcts = elem.find("fcts")
            if fcts is not None:
                for fct in fcts.findall("fct"):
                    fct_name = fct.text
                    for imp in imports:
                        if (str(imp["libname"]).upper() == str(name).upper()) & (str(imp["name"]).upper() == str(fct_name).upper()):
                            print(f"Library: {name}, Flag: {flag}, Description: {desc}")
                            print(f"Function: {fct_name}")
                            # Añadimos la coincidencia al diccionario
                            key = f"{name}: {fct_name}"
                            if key not in matches:
                                matches[key] = []
                            matches[key].append((name, fct_name))
            
            # Limpiar el elemento para liberar memoria
            elem.clear()
    return matches

# Llamar a la función con el archivo XML que deseas procesar
r2 = r2pipe.open("C:/Users/deeps_67sgwef/Desktop/DEEPSPY/ZIP-a-PNG-main/Resultados/1 exe/7z2408-x64.exe")
imports = json.loads(r2.cmd("iij")) 
process_xml('C:/Users/deeps_67sgwef/Desktop/DEEPSPY/ZIP-a-PNG-main/Extraer_Caracteristicas/functions.xml', imports)
