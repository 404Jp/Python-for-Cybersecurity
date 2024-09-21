import nmap

# Función para mostrar explicaciones de los parámetros
def mostrar_opciones():
    print("Este script te permitirá utilizar 'nmap'.")
    print("A continuación te explicamos algunos de los parámetros más utilizados:\n")
    print("-p-: Escanea todos los puertos.")
    print("--top-ports <n>: Escanea los n puertos más comunes.")
    print("-v: Modo verbose, muestra información más detallada durante el escaneo.")
    print("-n: No resuelve nombres DNS, solo usa direcciones IP.")
    print("-T<0-5>: Ajusta la velocidad del escaneo. 0 es el más lento (stealth), 5 el más rápido (agresivo).")
    print("-Pn: No hace ping a los hosts antes de escanear (útil si ICMP está bloqueado).")
    print("-sS: Escaneo SYN (stealth scan).")
    print("-sT: Escaneo de puertos TCP.")
    print("-sU: Escaneo de puertos UDP.")
    print("-sV: Detecta versiones de servicios en los puertos abiertos.")
    print("-A: Detección de sistema operativo y servicios.")
    print("-O: Detectar el sistema operativo del host.")
    print("-f: Fragmenta los paquetes para evitar detección por firewalls.")
    print("-D < señuelo >: Usar IPs señuelos para ocultar la IP real.")
    print("--spoof-mac <mac>: Falsifica la dirección MAC.")
    print("--traceroute: Ejecutar traceroute hacia el host.")
    print("--script <nombre>: Ejecutar scripts NSE para tareas específicas (como vulnerabilidades).\n")
    
def obtener_parametros():
    # Obtener la dirección IP o rango
    ip = input("Introduce la dirección IP o rango a escanear: ")
    
    # Preguntar si quiere escanear todos los puertos
    scan_all_ports = input("¿Quieres escanear todos los puertos (-p-)? (s/n): ").lower() == 's'
    if not scan_all_ports:
        # Si no, preguntar cuántos puertos comunes quiere escanear
        top_ports = input("Introduce el número de puertos más comunes a escanear (--top-ports <n>): ")
    else:
        top_ports = None
    
    # Preguntar por el modo verbose
    verbose = input("¿Quieres activar el modo verbose (-v)? (s/n): ").lower() == 's'
    
    # Preguntar si quiere desactivar la resolución DNS
    no_dns = input("¿Quieres desactivar la resolución de nombres DNS (-n)? (s/n): ").lower() == 's'
    
    # Preguntar por la intensidad de escaneo
    scan_timing = input("Introduce la velocidad del escaneo (0 más lento - 5 más rápido) [Por defecto 3]: ")
    if not scan_timing:
        scan_timing = '3'  # Valor por defecto
    
    # Preguntar si quiere desactivar el ping
    no_ping = input("¿Quieres desactivar el ping (-Pn)? (s/n): ").lower() == 's'
    
    # Preguntar por el tipo de escaneo
    scan_type = input("Elige el tipo de escaneo:\n1. Escaneo SYN (-sS)\n2. Escaneo TCP (-sT)\n3. Escaneo UDP (-sU)\nOmitir para no elegir: ")
    
    # Preguntar si quiere detección de versiones de servicios
    service_detection = input("¿Quieres activar la detección de versiones de servicios (-sV)? (s/n): ").lower() == 's'
    
    # Preguntar si quiere detección de sistema operativo y servicios
    os_detection = input("¿Quieres activar la detección de sistema operativo y servicios (-A)? (s/n): ").lower() == 's'
    
    # Preguntar si quiere detectar el sistema operativo
    detect_os = input("¿Quieres activar la detección de sistema operativo (-O)? (s/n): ").lower() == 's'
    
    # Preguntar si quiere ejecutar traceroute
    traceroute = input("¿Quieres ejecutar un traceroute (--traceroute)? (s/n): ").lower() == 's'
    
    # Preguntar si quiere usar paquetes fragmentados
    fragment = input("¿Quieres usar paquetes fragmentados para evitar detección (-f)? (s/n): ").lower() == 's'
    
    # Preguntar si quiere usar señuelos
    decoy = input("Introduce la lista de IPs señuelos separadas por comas (dejar vacío para no usar señuelos): ")
    
    # Preguntar si quiere falsificar la dirección MAC
    spoof_mac = input("Introduce la dirección MAC que quieres falsificar (o 'aleatorio' para una MAC aleatoria, deja vacío para no usar): ")
    
    # Preguntar si quiere ejecutar un script NSE
    script_nse = input("Introduce el nombre del script NSE que deseas ejecutar (o deja vacío para no usar): ")
    
    return ip, scan_all_ports, top_ports, verbose, no_dns, scan_timing, no_ping, scan_type, service_detection, os_detection, detect_os, traceroute, fragment, decoy, spoof_mac, script_nse

def ejecutar_nmap(ip, scan_all_ports, top_ports, verbose, no_dns, scan_timing, no_ping, scan_type, service_detection, os_detection, detect_os, traceroute, fragment, decoy, spoof_mac, script_nse):
    nm = nmap.PortScanner()

    # Construir el comando de escaneo
    options = ""
    
    if scan_all_ports:
        options += "-p- "
    else:
        options += f"--top-ports {top_ports} "

    if verbose:
        options += "-v "

    if no_dns:
        options += "-n "
    
    options += f"-T{scan_timing} "

    if no_ping:
        options += "-Pn "

    if scan_type == '1':
        options += "-sS "
    elif scan_type == '2':
        options += "-sT "
    elif scan_type == '3':
        options += "-sU "

    if service_detection:
        options += "-sV "

    if os_detection:
        options += "-A "

    if detect_os:
        options += "-O "

    if traceroute:
        options += "--traceroute "

    if fragment:
        options += "-f "

    if decoy:
        options += f"-D {decoy} "

    if spoof_mac:
        if spoof_mac.lower() == 'aleatorio':
            options += "--spoof-mac 0 "
        else:
            options += f"--spoof-mac {spoof_mac} "

    if script_nse:
        options += f"--script {script_nse} "

    # Ejecutar el escaneo
    print(f"Ejecutando nmap con las opciones: {options}")
    scan_result = nm.scan(hosts=ip, arguments=options)
    
    # Mostrar los resultados
    for host in nm.all_hosts():
        print(f"\nHost: {host}")
        print(f"Estado: {nm[host].state()}")
        if 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                print(f"Puerto: {port} \t Estado: {nm[host]['tcp'][port]['state']}")

if __name__ == "__main__":
    mostrar_opciones()
    ip, scan_all_ports, top_ports, verbose, no_dns, scan_timing, no_ping, scan_type, service_detection, os_detection, detect_os, traceroute, fragment, decoy, spoof_mac, script_nse = obtener_parametros()
    ejecutar_nmap(ip, scan_all_ports, top_ports, verbose, no_dns, scan_timing, no_ping, scan_type, service_detection, os_detection, detect_os, traceroute, fragment, decoy, spoof_mac, script_nse)
