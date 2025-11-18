"""
NetAuditBot - Módulo de Análisis de Seguridad
Analiza los resultados del escaneo y detecta vulnerabilidades
"""

import logging
from typing import Dict, List
from config import *

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """
    Clase para analizar resultados de escaneo y detectar problemas de seguridad
    """
    
    def __init__(self, scan_results: Dict):
        """
        Inicializa el analizador
        
        Args:
            scan_results: Resultados del escaneo de red
        """
        self.scan_results = scan_results
        self.vulnerabilities = []
        self.statistics = {
            'ALTO': 0,
            'MEDIO': 0,
            'BAJO': 0
        }
    
    def analyze_vulnerable_ports(self) -> List[Dict]:
        """
        Identifica puertos vulnerables conocidos
        
        Returns:
            Lista de vulnerabilidades encontradas
        """
        findings = []
        
        for host_ip, host_data in self.scan_results.items():
            for port_info in host_data['ports']:
                port_num = port_info['port']
                
                if port_num in VULNERABLE_PORTS:
                    vuln_info = VULNERABLE_PORTS[port_num]
                    
                    finding = {
                        'host': host_ip,
                        'hostname': host_data.get('hostname', 'N/A'),
                        'type': 'Puerto Vulnerable',
                        'risk': vuln_info['risk'],
                        'port': port_num,
                        'service': vuln_info['service'],
                        'description': f"Puerto {port_num} ({vuln_info['service']}) detectado",
                        'reason': vuln_info['reason'],
                        'recommendation': SECURITY_RECOMMENDATIONS.get(
                            vuln_info['service'],
                            "Revisar la necesidad de este servicio y considerar alternativas seguras"
                        )
                    }
                    
                    findings.append(finding)
                    self.statistics[vuln_info['risk']] += 1
                    
                    logger.warning(
                        f"[{vuln_info['risk']}] {host_ip}: Puerto vulnerable {port_num} ({vuln_info['service']})"
                    )
        
        return findings
    
    def analyze_unencrypted_services(self) -> List[Dict]:
        """
        Detecta servicios que transmiten datos sin cifrado
        
        Returns:
            Lista de servicios sin cifrado encontrados
        """
        findings = []
        
        for host_ip, host_data in self.scan_results.items():
            for port_info in host_data['ports']:
                service = port_info['service'].lower()
                
                if service in UNENCRYPTED_SERVICES:
                    finding = {
                        'host': host_ip,
                        'hostname': host_data.get('hostname', 'N/A'),
                        'type': 'Servicio sin Cifrado',
                        'risk': 'MEDIO',
                        'port': port_info['port'],
                        'service': port_info['service'],
                        'description': f"Servicio {service} sin cifrado en puerto {port_info['port']}",
                        'reason': "Los datos transmitidos pueden ser interceptados",
                        'recommendation': f"Migrar a versión cifrada del servicio ({service.upper()}S)"
                    }
                    
                    findings.append(finding)
                    self.statistics['MEDIO'] += 1
                    
                    logger.warning(
                        f"[MEDIO] {host_ip}: Servicio sin cifrado {service} en puerto {port_info['port']}"
                    )
        
        return findings
    
    def analyze_vulnerable_versions(self) -> List[Dict]:
        """
        Detecta versiones de software conocidas por ser vulnerables
        
        Returns:
            Lista de versiones vulnerables encontradas
        """
        findings = []
        
        for host_ip, host_data in self.scan_results.items():
            for port_info in host_data['ports']:
                product = port_info.get('product', '').lower()
                version = port_info.get('version', '')
                
                if not product or not version:
                    continue
                
                # Buscar coincidencias en versiones vulnerables
                for vuln_product, vuln_versions in VULNERABLE_VERSIONS.items():
                    if vuln_product in product:
                        for vuln_version in vuln_versions:
                            if vuln_version in version:
                                finding = {
                                    'host': host_ip,
                                    'hostname': host_data.get('hostname', 'N/A'),
                                    'type': 'Versión Vulnerable',
                                    'risk': 'ALTO',
                                    'port': port_info['port'],
                                    'service': port_info['service'],
                                    'description': f"{product} {version} tiene vulnerabilidades conocidas",
                                    'reason': f"La versión {version} de {product} tiene CVEs publicados",
                                    'recommendation': "Actualizar a la última versión estable del software"
                                }
                                
                                findings.append(finding)
                                self.statistics['ALTO'] += 1
                                
                                logger.warning(
                                    f"[ALTO] {host_ip}: Versión vulnerable {product} {version}"
                                )
        
        return findings
    
    def analyze_excessive_ports(self) -> List[Dict]:
        """
        Detecta hosts con demasiados puertos abiertos
        
        Returns:
            Lista de hosts con configuración insegura
        """
        findings = []
        
        for host_ip, host_data in self.scan_results.items():
            open_ports = host_data['open_ports_count']
            
            if open_ports > MAX_SAFE_OPEN_PORTS:
                finding = {
                    'host': host_ip,
                    'hostname': host_data.get('hostname', 'N/A'),
                    'type': 'Exceso de Puertos Abiertos',
                    'risk': 'MEDIO',
                    'port': 'N/A',
                    'service': 'Multiple',
                    'description': f"Host expone {open_ports} puertos abiertos (umbral: {MAX_SAFE_OPEN_PORTS})",
                    'reason': "Mayor superficie de ataque, aumenta el riesgo de compromiso",
                    'recommendation': "Cerrar puertos innecesarios y aplicar principio de mínimo privilegio"
                }
                
                findings.append(finding)
                self.statistics['MEDIO'] += 1
                
                logger.warning(
                    f"[MEDIO] {host_ip}: Exceso de puertos abiertos ({open_ports})"
                )
        
        return findings
    
    def analyze_all(self) -> Dict:
        """
        Ejecuta todos los análisis de seguridad
        
        Returns:
            Diccionario completo con todas las vulnerabilidades
        """
        logger.info("\n" + "=" * 60)
        logger.info("INICIANDO ANÁLISIS DE SEGURIDAD")
        logger.info("=" * 60)
        
        # Ejecutar todos los análisis
        vuln_ports = self.analyze_vulnerable_ports()
        unenc_services = self.analyze_unencrypted_services()
        vuln_versions = self.analyze_vulnerable_versions()
        excessive_ports = self.analyze_excessive_ports()
        
        # Consolidar todas las vulnerabilidades
        all_vulnerabilities = (
            vuln_ports + 
            unenc_services + 
            vuln_versions + 
            excessive_ports
        )
        
        self.vulnerabilities = all_vulnerabilities
        
        # Generar resumen
        analysis_summary = {
            'total_vulnerabilities': len(all_vulnerabilities),
            'by_risk': {
                'ALTO': self.statistics['ALTO'],
                'MEDIO': self.statistics['MEDIO'],
                'BAJO': self.statistics['BAJO']
            },
            'by_type': {
                'Puerto Vulnerable': len(vuln_ports),
                'Servicio sin Cifrado': len(unenc_services),
                'Versión Vulnerable': len(vuln_versions),
                'Exceso de Puertos': len(excessive_ports)
            },
            'vulnerabilities': all_vulnerabilities
        }
        
        # Log del resumen
        logger.info(f"\nTotal de vulnerabilidades encontradas: {len(all_vulnerabilities)}")
        logger.info(f"  - ALTO: {self.statistics['ALTO']}")
        logger.info(f"  - MEDIO: {self.statistics['MEDIO']}")
        logger.info(f"  - BAJO: {self.statistics['BAJO']}")
        logger.info("=" * 60)
        
        return analysis_summary
    
    def get_host_risk_score(self, host_ip: str) -> tuple:
        """
        Calcula el puntaje de riesgo para un host específico
        
        Args:
            host_ip: IP del host
            
        Returns:
            Tupla (score, risk_level)
        """
        score = 0
        host_vulns = [v for v in self.vulnerabilities if v['host'] == host_ip]
        
        for vuln in host_vulns:
            if vuln['risk'] == 'ALTO':
                score += 10
            elif vuln['risk'] == 'MEDIO':
                score += 5
            elif vuln['risk'] == 'BAJO':
                score += 2
        
        if score >= 20:
            risk_level = 'CRÍTICO'
        elif score >= 10:
            risk_level = 'ALTO'
        elif score >= 5:
            risk_level = 'MEDIO'
        else:
            risk_level = 'BAJO'
        
        return score, risk_level


def test_analyzer():
    """
    Función de prueba del analizador
    """
    # Datos de prueba simulados
    test_data = {
        '192.168.1.100': {
            'hostname': 'server01',
            'os': 'Linux',
            'ports': [
                {'port': 21, 'service': 'ftp', 'version': '2.0'},
                {'port': 22, 'service': 'ssh', 'version': '7.4'},
                {'port': 80, 'service': 'http', 'version': ''},
            ],
            'open_ports_count': 3
        }
    }
    
    analyzer = SecurityAnalyzer(test_data)
    results = analyzer.analyze_all()
    
    print(f"\nVulnerabilidades encontradas: {results['total_vulnerabilities']}")
    print(f"Riesgo ALTO: {results['by_risk']['ALTO']}")
    print(f"Riesgo MEDIO: {results['by_risk']['MEDIO']}")


if __name__ == "__main__":
    test_analyzer()