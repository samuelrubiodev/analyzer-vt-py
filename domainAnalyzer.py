from tools.domainTools import checkDomainIP
from tools.utils import removeDuplicates
import argparse, os
import time

"""
Script para analizar dominios o IPs utilizando la API de VirusTotal.
Permite analizar un único objetivo o múltiples desde un fichero.


Requiere la variable de entorno VT_API_KEY configurada con la clave de API de VirusTotal.

"""

description_text = """🔎 Analizador de Dominios/IPs con VirusTotal 🌍

    Esta herramienta consulta la API de VirusTotal 🦠 para analizar:
      1. Puntuaciones de seguridad (malicioso, sospechoso, etc.).
      2. Información geográfica (país, ciudad) de la IP.

    Debes elegir un modo de operación (obligatorio):
      🎯  -t, --target: Para un único Dominio o IP.
      📁  -f, --file:   Para procesar una lista desde un fichero.
    Opcionalmente, puedes excluir ciertos dominios de la verificación de IPs geolocalizadas:
        ❌  -e, --except-domain: Dominios separados por comas a excluir (por defecto: mshome.net).

    
    ⚠️ Nota Importante sobre los Límites de la API:
    La API pública de VirusTotal tiene límites estrictos de 4 peticiones por minuto.
    El script, si usas la función de enviar un fichero de texto, cuando hace 4 peticiones por minuto automáticamente esperará 1 minuto para poder seguir analizando las IPs y respetar los límites de uso.
    Si cuentas con una cuenta con más límites puedes utilizar opcionalmente el argumento -l o --limit 

"""

# Configuración del parser de argumentos
parser = argparse.ArgumentParser(
    description=description_text,
    formatter_class=argparse.RawTextHelpFormatter 
)

# Definición de argumentos
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-t", "--target", type=str, help="Dominio o IP a analizar.")
group.add_argument("-f", "--file", type=str, help="Fichero con lista de dominios o IPs a analizar.")

parser.add_argument("-e", "--except-domain", type=str, help="Excluir dominios de la verificación de IPs geolocalizadas separados por comas.")
parser.add_argument("-l", "--limit", type=int, default=4, help="Número máximo de peticiones por minuto (si tu cuenta lo permite).")

args = parser.parse_args()
api_key = os.getenv("VT_API_KEY")

# Verificación de la clave de API
if api_key is None:
    print("Error: La variable de entorno VT_API_KEY no está configurada.")
    exit(1)

# Procesamiento de dominios a excluir
if args.except_domain:
    domains_except = args.except_domain.split(",")
else:
    domains_except = ["mshome.net"]


# Validación para el argumento -e solo si -f está activo
if args.except_domain and not args.file:
    print("Error: El argumento -e solo puede usarse cuando el argumento -f está activo.")
    exit(1)

# Procesamiento según el modo seleccionado
if args.target:
    print(f"🎯 Analizando objetivo único: {args.target}...")
    resultado = checkDomainIP(args.target)
    print(resultado)
elif args.file:
    if not os.path.exists(args.file):
        print(f"Error: El fichero '{args.file}' no se ha encontrado.")
        exit(1)

    maxCount = args.limit
    count = 0

    print(f"📁 Analizando objetivos del fichero: {args.file}...")
    targets = removeDuplicates(args.file, domains_except)
    for target in targets:
        # Manejo del límite de la API
        if count == maxCount:
            print(f"\n⏳ Esperando 60 segundos para evitar límite de la API...")
            time.sleep(60)
            count = 0
        print(f"\n--- 🦠 Analizando: {target} ---")
        resultado = checkDomainIP(target)
        print(resultado)
        count += 1

print("\n✅ Análisis completado.")