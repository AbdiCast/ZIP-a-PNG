import r2pipe
import hashlib
import json
import os
from collections import defaultdict
from Extraer_Caracteristicas.entropia import calculate_entropy
from Extraer_Caracteristicas.entropia import calculate_file_entropy

def get_file_info(file_path):
    # Obtener nombre y tamaño del archivo
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    
    # Calcular los hashes MD5 y SHA-256
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    
    file_info = {
        "file_name": file_name,
        "file_size": f"{file_size // 1024}KB",
        "hashes": {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
    }
    
    return file_info

def extract_json_data(file_path):
    # Iniciar r2pipe y analizar el archivo
    r2 = r2pipe.open(file_path)
    #r2.cmd('aa')  # Análisis completo

    # Extraer información en JSON
    sections = json.loads(r2.cmd("iSj")) 
    imports = json.loads(r2.cmd("iij")) 
    strings = json.loads(r2.cmd("izj")) 
    resources = json.loads(r2.cmd("irj")) 
    timestamp = r2.cmdj("ij") 

    # Agrupar funciones
    grouped = defaultdict(list)
    for imp in imports:
        grouped[imp["libname"]].append(imp["name"])

    # Agrupar funciones
    grouped_rcs = defaultdict(list)
    for rcs in resources:
        grouped_rcs[rcs['type']].append(rcs["name"])

    # Agrupar funciones
    grouped_str = defaultdict(list)
    for str in strings:
        grouped_str[str['section']].append(str["string"])
        
    # Continuamos
    suspicious_dll = ["d"]
    suspicious_functions = []
    suspicious_strings = []

    entropy_data = calculate_file_entropy(file_path) # entropy_data =r2.cmd("iSj") #float(r2.cmd("p= asdfasdf").strip()) # 
    # Procesar strings sospechosos (ejemplo básico)
    #suspicious_strings = [s['string'] for s in strings['strings'] if "http" in s['string'] or "C2" in s['string'] or "APPDATA" in s['string']]
    
    for s in strings:  # Iterar sobre cada diccionario en la lista de strings
        string_value = s['string']  # Obtener el valor de la cadena
        # Comprobar si alguno de los términos sospechosos está presente en la cadena
        if "http" in string_value or "C2" in string_value or "APPDATA" in string_value:
            suspicious_strings.append(string_value)  # Agregar la cadena sospechosa a la lista
    

    
    # Armar estructura JSON
    analysis_data = {
        "compilation_timestamp": timestamp["bin"]['compiled'],
        
        "entropy": entropy_data,
        "imports": {
            "dlls": [{"libname": libname, "functions": functions} for libname, functions in grouped.items()],
            "suspicious_imports": suspicious_dll
        },
        "strings": {
            "total_strings": len(strings),
            "detalles": [{"section": section, "strings": strings} for section, strings in grouped_str.items()],
            "suspicious_strings": suspicious_strings
        },
        "sections": [
            {
                "name": section['name'],
                "virtual_size": section['vsize'],
                "raw_size": section['size'],
                "entropy": calculate_entropy(r2.cmdj(f"pxj {section['size']} @ {section['vaddr']}"))  # Manejo de ausencia de 'entropy'
            } for section in sections
        ],
        "resources": {
            "total_size": len(resources),
            "details": [{"type": types, "names": names} for types, names in grouped_rcs.items()],
           
        }
    }
    
    r2.quit()  # Cerrar la conexión con r2pipe
    return analysis_data

def extraer_caractiscticas(origin_file_path, dest_file_path):
    file_info = get_file_info(origin_file_path)
    analysis_data = extract_json_data(origin_file_path)
    
    final_output = {
        "file_info": file_info,
        "analysis": analysis_data
    }
    
    # Convertir a JSON y guardar en un archivo
    with open(dest_file_path, "w") as outfile:
        json.dump(final_output, outfile, indent=4)

if __name__ == "__main__":
    origin_file_path = "C:/Users/castr/Downloads/Ledger Live.exe"  # Cambia esto por el path de tu archivo PE
    dest_file_path = "analysis_output.json"
    extraer_caractiscticas(origin_file_path,dest_file_path)
