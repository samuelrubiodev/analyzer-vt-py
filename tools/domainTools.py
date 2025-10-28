import vt, os, requests, ipaddress, asyncio

"""
Module para obtener información geográfica y de seguridad de dominios e IPs utilizando la API de VirusTotal y el servicio ip-api.com.

Clases:
- IpInfo: Clase para almacenar y representar la información de una IP.

Funciones:
- is_ip(input_string): Verifica si una cadena dada es una dirección IP válida.
- checkDomainIpVT(domainIP): Función asíncrona que consulta la API de VirusTotal para obtener análisis de seguridad de una IP o dominio.
- checkDomainIP(domainIP): Función principal que obtiene información geográfica y de seguridad de una IP o dominio.

"""

class IpInfo:
    def __init__(self, ip, city, country, isp, asn, analysis):
        self.ip = ip
        self.city = city
        self.country = country
        self.isp = isp
        self.asn = asn
        self.analysis = analysis

    def __str__(self):
        return (
            f"📍 IP: {self.ip}\n"
            f"🏙️  Ciudad: {self.city}\n"
            f"🌍 País: {self.country}\n"
            f"🌐 ISP: {self.isp}\n"
            f"🏛️  ASN: {self.asn}\n"
            f"🦠 Análisis de VirusTotal: {self.analysis}"
        )
    
def is_ip(input_string):
    try:
        ipaddress.ip_address(input_string)
        return True
    except Exception:
        return False

async def checkDomainIpVT(domainIP):
    client = vt.Client(os.getenv("VT_API_KEY"))
    try:
        if is_ip(domainIP):
            analysis = await client.get_object_async(f"/ip_addresses/{domainIP}")
        else:
            url_with_scheme = domainIP
            if not domainIP.startswith(('http://', 'https://')):
                url_with_scheme = f"http://{domainIP}" 
            
            url_id = vt.url_id(url_with_scheme)
            analysis = await client.get_object_async(f"/urls/{url_id}")
    except vt.error.APIError as e:
        if e.code == 'NotFoundError' and not is_ip(domainIP):
            print(f"ℹ️ No hay información pública de '{domainIP}' en VirusTotal. Iniciando análisis... ⏳")
            analysis = await client.scan_url_async(domainIP)
            await client.wait_for_analysis_completion(analysis)
            analysis = await client.get_object_async(f"/urls/{url_id}")
        elif e.code == 'NotFoundError' and is_ip(domainIP):
            return f"ℹ️ {domainIP}: No hay información pública de esta IP en VirusTotal."
        else:
            return f"❌ Error de API VT: {e}"
    finally:
        await client.close_async()

    stats = analysis.last_analysis_stats
    analysis_stats = (
        f"    🔴 Malicioso: {stats.get('malicious', 0)}\n"
        f"    🟡 Sospechoso: {stats.get('suspicious', 0)}\n"
        f"    🟢 Inofensivo: {stats.get('harmless', 0)}\n"
        f"    🔵 Sin detectar: {stats.get('undetected', 0)}"
    )

    return f"\n{analysis_stats}"

def checkDomainIP(domainIP):
    try:
        result_domain = asyncio.run(checkDomainIpVT(domainIP))

        response = requests.get(f"http://ip-api.com/json/{domainIP}")
        data = response.json()
        if response.status_code == 200:
            return IpInfo(data.get("query"), data.get("city"), data.get("country"), data.get("isp"), data.get("as"), result_domain)
        else:
            return f"❌ Error: No se pudo obtener la información geográfica de {domainIP}."
    except Exception as e:
        return f"❌ Excepción inesperada al procesar {domainIP}: {e}"