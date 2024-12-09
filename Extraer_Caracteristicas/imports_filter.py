import xml.etree.ElementTree as ET

def process_xml(file_path):
    # Usamos iterparse para leer el XML de manera incremental
    context = ET.iterparse(file_path, events=("start", "end"))
    
    for event, elem in context:
        if event == "start" and elem.tag == "lib":
            # Procesamos los atributos del elemento <lib>
            name = elem.attrib.get("name")
            flag = elem.attrib.get("flag")
            desc = elem.attrib.get("desc")
            
            #print(f"Library: {name}, Flag: {flag}, Description: {desc}")
            
            # Buscar los elementos <fcts> y sus subelementos <fct>
            fcts = elem.find("fcts")
            if fcts is not None:
                for fct in fcts.findall("fct"):
                    fct_name = fct.text
                    #print(f"  Function: {fct_name}")
            
            # Limpiar el elemento para liberar memoria
            elem.clear()

# Llamar a la función con el archivo XML que deseas procesar
process_xml('functions.xml')
