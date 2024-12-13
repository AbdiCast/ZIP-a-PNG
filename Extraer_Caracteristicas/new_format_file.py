from Extraer_Caracteristicas.imports_filter import get_susp_imports
from Extraer_Caracteristicas.entropia import calculate_file_entropy
from Extraer_Caracteristicas.entropia import calculate_entropy

from collections import defaultdict
import hashlib
import r2pipe
import json
import os


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
    # Comentario import prueba #imports = [{'ordinal': 8, 'bind': 'NONE', 'type': 'FUNC', 'name': 'CreateHardLink', 'libname': 'kernel32.dll', 'plt': 4227348}, {'ordinal': 9, 'bind': 'NONE', 'type': 'FUNC', 'name': 'IsHungAppWindow', 'libname': 'USER32.dll', 'plt': 4227352}, {'ordinal': 10, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SQLConfigDriver', 'libname': 'odbccp32.dll', 'plt': 4227356}, {'ordinal': 11, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SearchPath', 'libname': 'kernel32.dll', 'plt': 4227360}, {'ordinal': 12, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetDlgItem', 'libname': 'USER32.dll', 'plt': 4227364}, {'ordinal': 13, 'bind': 'NONE', 'type': 'FUNC', 'name': 'IsDialogMessageW', 'libname': 'USER32.dll', 'plt': 4227368}, {'ordinal': 14, 'bind': 'NONE', 'type': 'FUNC', 'name': 'TranslateMessage', 'libname': 'USER32.dll', 'plt': 4227372}, {'ordinal': 15, 'bind': 'NONE', 'type': 'FUNC', 'name': 'DispatchMessageW', 'libname': 'USER32.dll', 'plt': 4227376}, {'ordinal': 16, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SetDlgItemTextW', 'libname': 'USER32.dll', 'plt': 4227380}, {'ordinal': 17, 'bind': 'NONE', 'type': 'FUNC', 'name': 'DestroyWindow', 'libname': 'USER32.dll', 'plt': 4227384}, {'ordinal': 1, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegSetValueExW', 'libname': 'ADVAPI32.dll', 'plt': 4227072}, {'ordinal': 2, 'bind': 'NONE', 'type': 'FUNC', 'name': 'OpenProcessToken', 'libname': 'ADVAPI32.dll', 'plt': 4227076}, {'ordinal': 3, 'bind': 'NONE', 'type': 'FUNC', 'name': 'LookupPrivilegeValueW', 'libname': 'ADVAPI32.dll', 'plt': 4227080}, {'ordinal': 4, 'bind': 'NONE', 'type': 'FUNC', 'name': 'AdjustTokenPrivileges', 'libname': 'ADVAPI32.dll', 'plt': 4227084}, {'ordinal': 5, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegQueryValueExW', 'libname': 'ADVAPI32.dll', 'plt': 4227088}, {'ordinal': 6, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegOpenKeyExW', 'libname': 'ADVAPI32.dll', 'plt': 4227092}, {'ordinal': 7, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegCloseKey', 'libname': 'ADVAPI32.dll', 'plt': 4227096}, {'ordinal': 8, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegCreateKeyExW', 'libname': 'ADVAPI32.dll', 'plt': 4227100}, {'ordinal': 1, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SHGetFolderPathW', 'libname': 'SHELL32.dll', 'plt': 4227304}, {'ordinal': 2, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SHBrowseForFolderW', 'libname': 'SHELL32.dll', 'plt': 4227308}, {'ordinal': 3, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SHGetPathFromIDListW', 'libname': 'SHELL32.dll', 'plt': 4227312}, {'ordinal': 1, 'bind': 'NONE', 'type': 'FUNC', 'name': '_exit', 'libname': 'MSVCRT.dll', 'plt': 4227224}, {'ordinal': 2, 'bind': 'NONE', 'type': 'FUNC', 'name': '_XcptFilter', 'libname': 'MSVCRT.dll', 'plt': 4227228}, {'ordinal': 3, 'bind': 'NONE', 'type': 'FUNC', 'name': '_acmdln', 'libname': 'MSVCRT.dll', 'plt': 4227232}, {'ordinal': 4, 'bind': 'NONE', 'type': 'FUNC', 'name': '__getmainargs', 'libname': 'MSVCRT.dll', 'plt': 4227236}, {'ordinal': 5, 'bind': 'NONE', 'type': 'FUNC', 'name': '_initterm', 'libname': 'MSVCRT.dll', 'plt': 4227240}, {'ordinal': 6, 'bind': 'NONE', 'type': 'FUNC', 'name': '__setusermatherr', 'libname': 'MSVCRT.dll', 'plt': 4227244}, {'ordinal': 7, 'bind': 'NONE', 'type': 'FUNC', 'name': '_adjust_fdiv', 'libname': 'MSVCRT.dll', 'plt': 4227248}, {'ordinal': 8, 'bind': 'NONE', 'type': 'FUNC', 'name': '__p__commode', 'libname': 'MSVCRT.dll', 'plt': 4227252}, {'ordinal': 9, 'bind': 'NONE', 'type': 'FUNC', 'name': '__p__fmode', 'libname': 'MSVCRT.dll', 'plt': 4227256}, {'ordinal': 10, 'bind': 'NONE', 'type': 'FUNC', 'name': '__set_app_type', 'libname': 'MSVCRT.dll', 'plt': 4227260}, {'ordinal': 11, 'bind': 'NONE', 'type': 'FUNC', 'name': '_except_handler3', 'libname': 'MSVCRT.dll', 'plt': 4227264}, {'ordinal': 12, 'bind': 'NONE', 'type': 'FUNC', 'name': '_controlfp', 'libname': 'MSVCRT.dll', 'plt': 4227268}, {'ordinal': 13, 'bind': 'NONE', 'type': 'FUNC', 'name': 'memcpy', 'libname': 'MSVCRT.dll', 'plt': 4227272}, {'ordinal': 14, 'bind': 'NONE', 'type': 'FUNC', 'name': 'memcmp', 'libname': 'MSVCRT.dll', 'plt': 4227276}, {'ordinal': 15, 'bind': 'NONE', 'type': 'FUNC', 'name': 'memmove', 'libname': 'MSVCRT.dll', 'plt': 4227280}, {'ordinal': 16, 'bind': 'NONE', 'type': 'FUNC', 'name': 'malloc', 'libname': 'MSVCRT.dll', 'plt': 4227284}, {'ordinal': 17, 'bind': 'NONE', 'type': 'FUNC', 'name': 'free', 'libname': 'MSVCRT.dll', 'plt': 4227288}, {'ordinal': 18, 'bind': 'NONE', 'type': 'FUNC', 'name': 'exit', 'libname': 'MSVCRT.dll', 'plt': 4227292}, {'ordinal': 19, 'bind': 'NONE', 'type': 'FUNC', 'name': 'memset', 'libname': 'MSVCRT.dll', 'plt': 4227296}, {'ordinal': 1, 'bind': 'NONE', 'type': 'FUNC', 'name': 'ReadFile', 'libname': 'KERNEL32.dll', 'plt': 4227108}, {'ordinal': 2, 'bind': 'NONE', 'type': 'FUNC', 'name': 'CloseHandle', 'libname': 'KERNEL32.dll', 'plt': 4227112}, {'ordinal': 3, 'bind': 'NONE', 'type': 'FUNC', 'name': 'CreateFileW', 'libname': 'KERNEL32.dll', 'plt': 4227116}, {'ordinal': 4, 'bind': 'NONE', 'type': 'FUNC', 'name': 'FormatMessageW', 'libname': 'KERNEL32.dll', 'plt': 4227120}, {'ordinal': 5, 'bind': 'NONE', 'type': 'FUNC', 'name': 'WriteFile', 'libname': 'KERNEL32.dll', 'plt': 4227124}, {'ordinal': 6, 'bind': 'NONE', 'type': 'FUNC', 'name': 'DeleteFileW', 'libname': 'KERNEL32.dll', 'plt': 4227128}, {'ordinal': 7, 'bind': 'NONE', 'type': 'FUNC', 'name': 'CreateDirectoryW', 'libname': 'KERNEL32.dll', 'plt': 4227132}, {'ordinal': 8, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetSystemDirectoryW', 'libname': 'KERNEL32.dll', 'plt': 4227136}, {'ordinal': 9, 'bind': 'NONE', 'type': 'FUNC', 'name': 'LoadLibraryW', 'libname': 'KERNEL32.dll', 'plt': 4227140}, {'ordinal': 10, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetModuleFileNameW', 'libname': 'KERNEL32.dll', 'plt': 4227144}, {'ordinal': 11, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetFileAttributesW', 'libname': 'KERNEL32.dll', 'plt': 4227148}, {'ordinal': 12, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SetFilePointer', 'libname': 'KERNEL32.dll', 'plt': 4227152}, {'ordinal': 13, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetVersion', 'libname': 'KERNEL32.dll', 'plt': 4227156}, {'ordinal': 14, 'bind': 'NONE', 'type': 'FUNC', 'name': 'LoadLibraryExW', 'libname': 'KERNEL32.dll', 'plt': 4227160}, {'ordinal': 15, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetModuleHandleA', 'libname': 'KERNEL32.dll', 'plt': 4227164}, {'ordinal': 16, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetStartupInfoA', 'libname': 'KERNEL32.dll', 'plt': 4227168}, {'ordinal': 17, 'bind': 'NONE', 'type': 'FUNC', 'name': 'LocalFree', 'libname': 'KERNEL32.dll', 'plt': 4227172}, {'ordinal': 18, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SetFileAttributesW', 'libname': 'KERNEL32.dll', 'plt': 4227176}, {'ordinal': 19, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SetFileTime', 'libname': 'KERNEL32.dll', 'plt': 4227180}, {'ordinal': 20, 'bind': 'NONE', 'type': 'FUNC', 'name': 'MoveFileExW', 'libname': 'KERNEL32.dll', 'plt': 4227184}, {'ordinal': 21, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetLastError', 'libname': 'KERNEL32.dll', 'plt': 4227188}, {'ordinal': 22, 'bind': 'NONE', 'type': 'FUNC', 'name': 'lstrcatW', 'libname': 'KERNEL32.dll', 'plt': 4227192}, {'ordinal': 23, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetCommandLineW', 'libname': 'KERNEL32.dll', 'plt': 4227196}, {'ordinal': 24, 'bind': 'NONE', 'type': 'FUNC', 'name': 'lstrcpyW', 'libname': 'KERNEL32.dll', 'plt': 4227200}, {'ordinal': 25, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetModuleHandleW', 'libname': 'KERNEL32.dll', 'plt': 4227204}, {'ordinal': 26, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetProcAddress', 'libname': 'KERNEL32.dll', 'plt': 4227208}, {'ordinal': 27, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetCurrentProcess', 'libname': 'KERNEL32.dll', 'plt': 4227212}, {'ordinal': 28, 'bind': 'NONE', 'type': 'FUNC', 'name': 'lstrlenW', 'libname': 'KERNEL32.dll', 'plt': 4227216}]
    strings = json.loads(r2.cmd("izj")) 
    resources = json.loads(r2.cmd("irj")) 
    timestamp = r2.cmdj("ij") 

    # Agrupar funciones por libreria 
    grouped_imp = defaultdict(list)
    for imp in imports:
        grouped_imp[imp["libname"]].append(imp["name"])

    # Agrupar recursos por tipo
    grouped_rcs = defaultdict(list)
    for rcs in resources:
        grouped_rcs[rcs['type']].append(rcs["name"])

    # Agrupar strings por secciones
    grouped_str = defaultdict(list)
    for str in strings:
        grouped_str[str['section']].append(str["string"])
        
    # Continuamos
    suspicious_imports = get_susp_imports(imports)
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
            "dlls": [{"libname": libname, "functions": functions} for libname, functions in grouped_imp.items()],
            "suspicious_imports": suspicious_imports
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
