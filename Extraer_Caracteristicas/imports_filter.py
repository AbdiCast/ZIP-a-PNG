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
            lib_name = elem.attrib.get("name")
            flag = elem.attrib.get("flag")
            desc = elem.attrib.get("desc")

            # Buscar los elementos <fcts> y sus subelementos <fct>
            fcts = elem.find("fcts")
            if fcts is not None:
                for fct in fcts.findall("fct"):
                    fct_name = fct.text
                    for imp in imports:
                        imp_lib = imp["libname"]
                        imp_fct = imp["name"]

                        if (str(imp_lib).upper() == str(lib_name).upper()) and (str(imp_fct).upper() == str(fct_name).upper()):
                            #print(f"Library: {lib_name}, Flag: {flag}, Description: {desc}")
                            #print(f"Function: {fct_name}")
                            # Añadimos la coincidencia al diccionario
                            if lib_name not in matches:
                                matches[lib_name] = []
                            matches[lib_name].append(fct_name)
                    
            # Limpiar el elemento para liberar memoria
            elem.clear()
    return matches
def get_susp_imports(imports):
    return process_xml('./Extraer_Caracteristicas/functions.xml', imports)


if __name__ == "__main__":
    # Llamar a la función con el archivo XML que deseas procesar
    r2 = r2pipe.open("./Resultados/1 exe/7z2408-x64.exe")
    imports = json.loads(r2.cmd("iij")) 
    imports = [{'ordinal': 8, 'bind': 'NONE', 'type': 'FUNC', 'name': 'CreateHardLink', 'libname': 'kernel32.dll', 'plt': 4227348}, {'ordinal': 9, 'bind': 'NONE', 'type': 'FUNC', 'name': 'IsHungAppWindow', 'libname': 'USER32.dll', 'plt': 4227352}, {'ordinal': 10, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SQLConfigDriver', 'libname': 'odbccp32.dll', 'plt': 4227356}, {'ordinal': 11, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SearchPath', 'libname': 'kernel32.dll', 'plt': 4227360}, {'ordinal': 12, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetDlgItem', 'libname': 'USER32.dll', 'plt': 4227364}, {'ordinal': 13, 'bind': 'NONE', 'type': 'FUNC', 'name': 'IsDialogMessageW', 'libname': 'USER32.dll', 'plt': 4227368}, {'ordinal': 14, 'bind': 'NONE', 'type': 'FUNC', 'name': 'TranslateMessage', 'libname': 'USER32.dll', 'plt': 4227372}, {'ordinal': 15, 'bind': 'NONE', 'type': 'FUNC', 'name': 'DispatchMessageW', 'libname': 'USER32.dll', 'plt': 4227376}, {'ordinal': 16, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SetDlgItemTextW', 'libname': 'USER32.dll', 'plt': 4227380}, {'ordinal': 17, 'bind': 'NONE', 'type': 'FUNC', 'name': 'DestroyWindow', 'libname': 'USER32.dll', 'plt': 4227384}, {'ordinal': 1, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegSetValueExW', 'libname': 'ADVAPI32.dll', 'plt': 4227072}, {'ordinal': 2, 'bind': 'NONE', 'type': 'FUNC', 'name': 'OpenProcessToken', 'libname': 'ADVAPI32.dll', 'plt': 4227076}, {'ordinal': 3, 'bind': 'NONE', 'type': 'FUNC', 'name': 'LookupPrivilegeValueW', 'libname': 'ADVAPI32.dll', 'plt': 4227080}, {'ordinal': 4, 'bind': 'NONE', 'type': 'FUNC', 'name': 'AdjustTokenPrivileges', 'libname': 'ADVAPI32.dll', 'plt': 4227084}, {'ordinal': 5, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegQueryValueExW', 'libname': 'ADVAPI32.dll', 'plt': 4227088}, {'ordinal': 6, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegOpenKeyExW', 'libname': 'ADVAPI32.dll', 'plt': 4227092}, {'ordinal': 7, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegCloseKey', 'libname': 'ADVAPI32.dll', 'plt': 4227096}, {'ordinal': 8, 'bind': 'NONE', 'type': 'FUNC', 'name': 'RegCreateKeyExW', 'libname': 'ADVAPI32.dll', 'plt': 4227100}, {'ordinal': 1, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SHGetFolderPathW', 'libname': 'SHELL32.dll', 'plt': 4227304}, {'ordinal': 2, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SHBrowseForFolderW', 'libname': 'SHELL32.dll', 'plt': 4227308}, {'ordinal': 3, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SHGetPathFromIDListW', 'libname': 'SHELL32.dll', 'plt': 4227312}, {'ordinal': 1, 'bind': 'NONE', 'type': 'FUNC', 'name': '_exit', 'libname': 'MSVCRT.dll', 'plt': 4227224}, {'ordinal': 2, 'bind': 'NONE', 'type': 'FUNC', 'name': '_XcptFilter', 'libname': 'MSVCRT.dll', 'plt': 4227228}, {'ordinal': 3, 'bind': 'NONE', 'type': 'FUNC', 'name': '_acmdln', 'libname': 'MSVCRT.dll', 'plt': 4227232}, {'ordinal': 4, 'bind': 'NONE', 'type': 'FUNC', 'name': '__getmainargs', 'libname': 'MSVCRT.dll', 'plt': 4227236}, {'ordinal': 5, 'bind': 'NONE', 'type': 'FUNC', 'name': '_initterm', 'libname': 'MSVCRT.dll', 'plt': 4227240}, {'ordinal': 6, 'bind': 'NONE', 'type': 'FUNC', 'name': '__setusermatherr', 'libname': 'MSVCRT.dll', 'plt': 4227244}, {'ordinal': 7, 'bind': 'NONE', 'type': 'FUNC', 'name': '_adjust_fdiv', 'libname': 'MSVCRT.dll', 'plt': 4227248}, {'ordinal': 8, 'bind': 'NONE', 'type': 'FUNC', 'name': '__p__commode', 'libname': 'MSVCRT.dll', 'plt': 4227252}, {'ordinal': 9, 'bind': 'NONE', 'type': 'FUNC', 'name': '__p__fmode', 'libname': 'MSVCRT.dll', 'plt': 4227256}, {'ordinal': 10, 'bind': 'NONE', 'type': 'FUNC', 'name': '__set_app_type', 'libname': 'MSVCRT.dll', 'plt': 4227260}, {'ordinal': 11, 'bind': 'NONE', 'type': 'FUNC', 'name': '_except_handler3', 'libname': 'MSVCRT.dll', 'plt': 4227264}, {'ordinal': 12, 'bind': 'NONE', 'type': 'FUNC', 'name': '_controlfp', 'libname': 'MSVCRT.dll', 'plt': 4227268}, {'ordinal': 13, 'bind': 'NONE', 'type': 'FUNC', 'name': 'memcpy', 'libname': 'MSVCRT.dll', 'plt': 4227272}, {'ordinal': 14, 'bind': 'NONE', 'type': 'FUNC', 'name': 'memcmp', 'libname': 'MSVCRT.dll', 'plt': 4227276}, {'ordinal': 15, 'bind': 'NONE', 'type': 'FUNC', 'name': 'memmove', 'libname': 'MSVCRT.dll', 'plt': 4227280}, {'ordinal': 16, 'bind': 'NONE', 'type': 'FUNC', 'name': 'malloc', 'libname': 'MSVCRT.dll', 'plt': 4227284}, {'ordinal': 17, 'bind': 'NONE', 'type': 'FUNC', 'name': 'free', 'libname': 'MSVCRT.dll', 'plt': 4227288}, {'ordinal': 18, 'bind': 'NONE', 'type': 'FUNC', 'name': 'exit', 'libname': 'MSVCRT.dll', 'plt': 4227292}, {'ordinal': 19, 'bind': 'NONE', 'type': 'FUNC', 'name': 'memset', 'libname': 'MSVCRT.dll', 'plt': 4227296}, {'ordinal': 1, 'bind': 'NONE', 'type': 'FUNC', 'name': 'ReadFile', 'libname': 'KERNEL32.dll', 'plt': 4227108}, {'ordinal': 2, 'bind': 'NONE', 'type': 'FUNC', 'name': 'CloseHandle', 'libname': 'KERNEL32.dll', 'plt': 4227112}, {'ordinal': 3, 'bind': 'NONE', 'type': 'FUNC', 'name': 'CreateFileW', 'libname': 'KERNEL32.dll', 'plt': 4227116}, {'ordinal': 4, 'bind': 'NONE', 'type': 'FUNC', 'name': 'FormatMessageW', 'libname': 'KERNEL32.dll', 'plt': 4227120}, {'ordinal': 5, 'bind': 'NONE', 'type': 'FUNC', 'name': 'WriteFile', 'libname': 'KERNEL32.dll', 'plt': 4227124}, {'ordinal': 6, 'bind': 'NONE', 'type': 'FUNC', 'name': 'DeleteFileW', 'libname': 'KERNEL32.dll', 'plt': 4227128}, {'ordinal': 7, 'bind': 'NONE', 'type': 'FUNC', 'name': 'CreateDirectoryW', 'libname': 'KERNEL32.dll', 'plt': 4227132}, {'ordinal': 8, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetSystemDirectoryW', 'libname': 'KERNEL32.dll', 'plt': 4227136}, {'ordinal': 9, 'bind': 'NONE', 'type': 'FUNC', 'name': 'LoadLibraryW', 'libname': 'KERNEL32.dll', 'plt': 4227140}, {'ordinal': 10, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetModuleFileNameW', 'libname': 'KERNEL32.dll', 'plt': 4227144}, {'ordinal': 11, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetFileAttributesW', 'libname': 'KERNEL32.dll', 'plt': 4227148}, {'ordinal': 12, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SetFilePointer', 'libname': 'KERNEL32.dll', 'plt': 4227152}, {'ordinal': 13, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetVersion', 'libname': 'KERNEL32.dll', 'plt': 4227156}, {'ordinal': 14, 'bind': 'NONE', 'type': 'FUNC', 'name': 'LoadLibraryExW', 'libname': 'KERNEL32.dll', 'plt': 4227160}, {'ordinal': 15, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetModuleHandleA', 'libname': 'KERNEL32.dll', 'plt': 4227164}, {'ordinal': 16, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetStartupInfoA', 'libname': 'KERNEL32.dll', 'plt': 4227168}, {'ordinal': 17, 'bind': 'NONE', 'type': 'FUNC', 'name': 'LocalFree', 'libname': 'KERNEL32.dll', 'plt': 4227172}, {'ordinal': 18, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SetFileAttributesW', 'libname': 'KERNEL32.dll', 'plt': 4227176}, {'ordinal': 19, 'bind': 'NONE', 'type': 'FUNC', 'name': 'SetFileTime', 'libname': 'KERNEL32.dll', 'plt': 4227180}, {'ordinal': 20, 'bind': 'NONE', 'type': 'FUNC', 'name': 'MoveFileExW', 'libname': 'KERNEL32.dll', 'plt': 4227184}, {'ordinal': 21, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetLastError', 'libname': 'KERNEL32.dll', 'plt': 4227188}, {'ordinal': 22, 'bind': 'NONE', 'type': 'FUNC', 'name': 'lstrcatW', 'libname': 'KERNEL32.dll', 'plt': 4227192}, {'ordinal': 23, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetCommandLineW', 'libname': 'KERNEL32.dll', 'plt': 4227196}, {'ordinal': 24, 'bind': 'NONE', 'type': 'FUNC', 'name': 'lstrcpyW', 'libname': 'KERNEL32.dll', 'plt': 4227200}, {'ordinal': 25, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetModuleHandleW', 'libname': 'KERNEL32.dll', 'plt': 4227204}, {'ordinal': 26, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetProcAddress', 'libname': 'KERNEL32.dll', 'plt': 4227208}, {'ordinal': 27, 'bind': 'NONE', 'type': 'FUNC', 'name': 'GetCurrentProcess', 'libname': 'KERNEL32.dll', 'plt': 4227212}, {'ordinal': 28, 'bind': 'NONE', 'type': 'FUNC', 'name': 'lstrlenW', 'libname': 'KERNEL32.dll', 'plt': 4227216}]
    matches = process_xml('./Extraer_Caracteristicas/functions.xml', imports)
    print(matches)
    
        