def removeDuplicates(sourcePathFile, domainsExcepts):
    try:
        with open(sourcePathFile, 'r', encoding='utf-16') as f:
            lineas = f.readlines()
        
        print(f"ℹ️ Archivo original '{sourcePathFile}' leído: {len(lineas)} líneas encontradas.")

        lineas_unicas = set()
        for linea in lineas:
            linea_limpia = linea.strip()
            if linea_limpia and linea_limpia.endswith(tuple(domainsExcepts)) is False:
                lineas_unicas.add(linea_limpia)
        return lineas_unicas
    except FileNotFoundError:
        print(f"Error: No se pudo encontrar el archivo '{sourcePathFile}'.")
    except Exception as e:
        print(f"❌ Ha ocurrido un error: {e}")