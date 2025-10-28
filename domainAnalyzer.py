from tools.domainTools import checkDomainIP
from tools.utils import removeDuplicates
import argparse, os

"""
Script para analizar dominios o IPs utilizando la API de VirusTotal.
Permite analizar un único objetivo o múltiples desde un fichero.


Requiere la variable de entorno VT_API_KEY configurada con la clave de API de VirusTotal.

"""

description_text = """
    🔎 Analizador de Dominios/IPs con VirusTotal 🌍

    Esta herramienta consulta la API de VirusTotal 🦠 para analizar:
      1. Puntuaciones de seguridad (malicioso, sospechoso, etc.).
      2. Información geográfica (país, ciudad) de la IP.

    Debes elegir un modo de operación (obligatorio):
      🎯  -t, --target: Para un único Dominio o IP.
      📁  -f, --file:   Para procesar una lista desde un fichero.
    Opcionalmente, puedes excluir ciertos dominios de la verificación de IPs geolocalizadas:
        ❌  -e, --except-domain: Dominios separados por comas a excluir (por defecto: mshome.net).
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

args = parser.parse_args()
api_key = os.getenv("VT_API_KEY")

if api_key is None:
    print("Error: La variable de entorno VT_API_KEY no está configurada.")
    exit(1)

if args.except_domain:
    domains_except = args.except_domain.split(",")
else:
    domains_except = ["mshome.net"]


# Procesamiento según el modo seleccionado
if args.target:
    print(f"🎯 Analizando objetivo único: {args.target}...")
    resultado = checkDomainIP(args.target)
    print(resultado)
elif args.file:
    if not os.path.exists(args.file):
        print(f"Error: El fichero '{args.file}' no se ha encontrado.")
        exit(1)

    print(f"📁 Analizando objetivos del fichero: {args.file}...")
    targets = removeDuplicates(args.file, domains_except)
    for target in targets:
        print(f"\n--- 🦠 Analizando: {target} ---")
        resultado = checkDomainIP(target)
        print(resultado)

print("\n✅ Análisis completado.")