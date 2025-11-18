"""
NetAuditBot - Módulo de Escaneo
Realiza el descubrimiento de hosts y escaneo de puertos
"""

import nmap
import logging
from typing import Dict, List, Optional
from config import *

# Configurar logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, LOG_FILENAME), encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


class NetworkScanner:
    """
    Clase para realizar escaneo de red usando Nmap
    """
    
    def __init__(self, target: str):
        """
        Inicializa el escáner
        
        Args:
            target: Rango de red o IP a escanear (ej: 192.168.1.0/24)
        """
        self.target = target
        self.nm = nmap.PortScanner()
        self.scan_results = {}
        logger.info(f"Scanner inicializado para target: {target}")
    
    def discover_hosts(self) -> List[str]:
        """
        Descubre hosts activos en la red
        
        Returns:
            Lista de IPs de hosts activos
        """
        logger.info(MESSAGES["scan_start"])
        try:
            # Ping sweep para descubrir hosts
            self.nm.scan(hosts=self.target, arguments='-sn')
            
            active_hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    active_hosts.append(host)
                    logger.info(f"Host activo encontrado: {host}")
            
            logger.info(f"Total de hosts activos: {len(active_hosts)}")
            return active_hosts
            
        except Exception as e:
            logger.error(f"{MESSAGES['scan_error']}: {str(e)}")
            return []
    
    def scan_host(self, host: str) -> Dict:
        """
        Escanea un host específico para detectar puertos y servicios
        
        Args:
            host: IP del host a escanear
            
        Returns:
            Diccionario con información del host
        """
        logger.info(f"Escaneando host: {host}")
        
        try:
            # Escaneo de puertos y servicios
            self.nm.scan(
                hosts=host,
                ports=COMMON_PORTS,
                arguments=NMAP_ARGUMENTS
            )
            
            host_info = {
                'ip': host,
                'hostname': '',
                'state': 'up',
                'os': '',
                'ports': [],
                'open_ports_count': 0
            }
            
            if host in self.nm.all_hosts():
                # Información básica del host
                if 'hostnames' in self.nm[host]:
                    hostnames = self.nm[host]['hostnames']
                    if hostnames and len(hostnames) > 0:
                        host_info['hostname'] = hostnames[0].get('name', '')
                
                # Detección de OS
                if 'osmatch' in self.nm[host]:
                    os_matches = self.nm[host]['osmatch']
                    if os_matches and len(os_matches) > 0:
                        host_info['os'] = os_matches[0].get('name', 'Desconocido')
                
                # Información de puertos
                if 'tcp' in self.nm[host]:
                    for port, port_info in self.nm[host]['tcp'].items():
                        if port_info['state'] == 'open':
                            port_data = {
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            }
                            host_info['ports'].append(port_data)
                            host_info['open_ports_count'] += 1
                            
                            logger.info(f"  Puerto {port} abierto: {port_data['service']}")
            
            return host_info
            
        except Exception as e:
            logger.error(f"Error escaneando {host}: {str(e)}")
            return {
                'ip': host,
                'hostname': '',
                'state': 'error',
                'os': '',
                'ports': [],
                'open_ports_count': 0,
                'error': str(e)
            }
    
    def scan_network(self) -> Dict[str, Dict]:
        """
        Escanea toda la red descubriendo hosts y analizándolos
        
        Returns:
            Diccionario con todos los hosts escaneados
        """
        logger.info("=" * 60)
        logger.info(f"Iniciando escaneo completo de red: {self.target}")
        logger.info("=" * 60)
        
        # Descubrir hosts activos
        active_hosts = self.discover_hosts()
        
        if not active_hosts:
            logger.warning(MESSAGES["no_hosts_found"])
            return {}
        
        # Escanear cada host
        scan_results = {}
        total_hosts = len(active_hosts)
        
        for idx, host in enumerate(active_hosts, 1):
            logger.info(f"\n[{idx}/{total_hosts}] Procesando host: {host}")
            host_info = self.scan_host(host)
            scan_results[host] = host_info
        
        self.scan_results = scan_results
        logger.info("=" * 60)
        logger.info(MESSAGES["scan_complete"])
        logger.info("=" * 60)
        
        return scan_results
    
    def get_summary(self) -> Dict:
        """
        Genera un resumen del escaneo
        
        Returns:
            Diccionario con estadísticas del escaneo
        """
        total_hosts = len(self.scan_results)
        total_open_ports = sum(
            host['open_ports_count'] 
            for host in self.scan_results.values()
        )
        
        # Contar servicios únicos
        services = set()
        for host in self.scan_results.values():
            for port in host['ports']:
                services.add(port['service'])
        
        summary = {
            'target': self.target,
            'total_hosts': total_hosts,
            'total_open_ports': total_open_ports,
            'unique_services': len(services),
            'services_list': list(services),
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return summary


def test_scanner():
    """
    Función de prueba del escáner
    """
    # Ejemplo de uso
    target = "192.168.1.0/24"
    scanner = NetworkScanner(target)
    results = scanner.scan_network()
    summary = scanner.get_summary()
    
    print("\n" + "=" * 60)
    print("RESUMEN DEL ESCANEO")
    print("=" * 60)
    print(f"Red objetivo: {summary['target']}")
    print(f"Hosts encontrados: {summary['total_hosts']}")
    print(f"Total de puertos abiertos: {summary['total_open_ports']}")
    print(f"Servicios únicos: {summary['unique_services']}")
    print("=" * 60)


if __name__ == "__main__":
    test_scanner()