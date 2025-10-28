# 🔎 Analizador de Dominios/IPs con VirusTotal 🌍

Este es un script de Python diseñado para automatizar el análisis de reputación y geolocalización de dominios e IPs. La herramienta utiliza las APIs de **VirusTotal** (para el análisis de seguridad) y **ip-api.com** (para la información geográfica).

El script puede funcionar en dos modos: analizando un único objetivo o procesando una lista de objetivos desde un archivo de texto.

## ✨ Características Principales

* **Doble Análisis:** Obtiene tanto la reputación de seguridad de VirusTotal como la información de geolocalización (País, Ciudad, ISP) de la IP.
* **Análisis en Lote:** Procesa archivos `.txt` (generados, por ejemplo, por Tshark o Zeek) que contienen múltiples dominios o IPs.
* **Escaneo Activo en VT:** Si un dominio no tiene un análisis reciente en VirusTotal, el script **solicitará un nuevo escaneo automáticamente** y esperará a que se complete para obtener el resultado.
* **Limpieza de Datos:** Filtra automáticamente líneas duplicadas y dominios "ruido" (como `.mshome.net` por defecto).
* **Manejo de Codificación:** Preparado para leer archivos de entrada en `utf-16`, un formato común al exportar desde Tshark en Windows.

## 🛠️ Requisitos e Instalación

### 1. Requisitos Previos

* Python 3.x
* Una clave de API de **VirusTotal**.

### 2. Instalación de Librerías

Necesitarás las librerías `vt-py` (para VirusTotal) y `requests` (para ip-api).

```bash
pip install vt-py requests
```

### 3. Configuración de la API Key

El script **requiere** que tu clave de API de VirusTotal esté configurada como una variable de entorno llamada `VT_API_KEY`.

En **Windows (CMD)**:

```cmd
set VT_API_KEY="tu_clave_de_api_aqui"
```

En Windows **(PowerShell)**:

```PowerShell
$env:VT_API_KEY="tu_clave_de_api_aqui"
```

En **Linux/macOS**:
```bash
export VT_API_KEY="tu_clave_de_api_aqui"
```

(Para hacerla permanente, añádela a tu `.bashrc` o `.zshrc`).

## 🚀 Uso

El script se ejecuta desde la línea de comandos usando `domainAnalyzer.py`.

### Ver la Ayuda

```bash
python domainAnalyzer.py -h
```

#### Modo 1: Analizar un Único Objetivo (`-t` o `--target`)

Proporciona un dominio o una IP para un análisis rápido.

```bash
python domainAnalyzer.py -t google.com
```

Salida de ejemplo:

```
🎯 Analizando objetivo único: google.com...
--- 🦠 Analizando: google.com ---
📍 IP: 142.250.184.78
🏙️  Ciudad: Madrid
🌍 País: Spain
🌐 ISP: Google LLC
🏛️  ASN: AS15169 Google LLC
🦠 Análisis de VirusTotal:
    🔴 Malicioso: 0
    🟡 Sospechoso: 0
    🟢 Inofensivo: 93
    🔵 Sin detectar: 4

✅ Análisis completado.
```

#### Modo 2: Analizar desde un Fichero (`-f` o `--file`)

Procesa una lista de dominios/IPs (separados por saltos de línea) desde un archivo.

```bash
python domainAnalyzer.py -f mi_lista_de_dominios.txt
```

Salida de ejemplo:


```
📁 Analizando objetivos del fichero: mi_lista_de_dominios.txt...
ℹ️ Archivo original 'mi_lista_de_dominios.txt' leído: 120 líneas encontradas.

--- 🦠 Analizando: cuevana-4.com ---
ℹ️ No hay información pública de 'cuevana-4.com' en VirusTotal. Iniciando análisis... ⏳
📍 IP: 104.21.90.160
🏙️  Ciudad: San Francisco
🌍 País: United States
🌐 ISP: Cloudflare, Inc.
🏛️  ASN: AS13335 CLOUDFLARENET
🦠 Análisis de VirusTotal:
    🔴 Malicioso: 1
    🟡 Sospechoso: 0
    🟢 Inofensivo: 89
    🔵 Sin detectar: 3

--- 🦠 Analizando: torchfriendlypay.com ---
📍 IP: 172.67.199.11
🏙️  Ciudad: San Francisco
...
(y así sucesivamente con todos los dominios únicos)
...
✅ Análisis completado.
```

#### Opción: Excluir Dominios (`-e` o `--except-domain`)

Puedes pasar una lista de sufijos de dominio (separados por comas) para que sean ignorados durante el procesamiento del archivo. El valor por defecto ya excluye `mshome.net`

```bash
# Excluir dominios .local y .lan
python domainAnalyzer.py -f mi_lista.txt -e ".local,.lan"
```

---

### ⚠️ Nota Importante sobre los Límites de la API

La API pública de VirusTotal tiene límites estrictos (generalmente 4 peticiones por minuto).

La función de solicitar un nuevo escaneo (`scan_url_async`) consume una petición y puede tardar varios minutos en completarse. Si tu lista de dominios contiene muchos que no están en VT, el script tardará mucho tiempo en completarse (15+ segundos por cada petición) para respetar estos límites.