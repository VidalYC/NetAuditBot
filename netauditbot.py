#!/usr/bin/env python3
"""
NetAuditBot - Herramienta de Auditoría de Red Automatizada
Autor: NetAuditBot Team
Versión: 1.0.0

Descripción:
    Herramienta que realiza escaneo de red, análisis de seguridad
    y genera reportes automatizados en formato HTML.

Uso:
    python netauditbot.py <red> [opciones]
    
Ejemplo:
    python netauditbot.py 192.168.1.0/24
    python netauditbot.py 192.168.1.100-120
"""

import argparse
import sys
import os
import time
from datetime import datetime

# Importar módulos propios
from config import *
from scanner import NetworkScanner
from security_analyzer import SecurityAnalyzer
from report_generator import ReportGenerator

# Banner ASCII
BANNER = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ███╗   ██╗███████╗████████╗                            ║
║   ████╗  ██║██╔════╝╚══██╔══╝                            ║
║   ██╔██╗ ██║█████╗     ██║                               ║
║   ██║╚██╗██║██╔══╝     ██║                               ║
║   ██║ ╚████║███████╗   ██║                               ║
║   ╚═╝  ╚═══╝╚══════╝   ╚═╝                               ║
║                                                          ║
║    █████╗ ██╗   ██╗██████╗ ██╗████████╗                  ║
║   ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝                  ║
║   ███████║██║   ██║██║  ██║██║   ██║                     ║
║   ██╔══██║██║   ██║██║  ██║██║   ██║                     ║
║   ██║  ██║╚██████╔╝██████╔╝██║   ██║                     ║
║   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝                     ║
║                                                          ║
║   ██████╗  ██████╗ ████████╗                             ║
║   ██╔══██╗██╔═══██╗╚══██╔══╝                             ║
║   ██████╔╝██║   ██║   ██║                                ║
║   ██╔══██╗██║   ██║   ██║                                ║
║   ██████╔╝╚██████╔╝   ██║                                ║
║   ╚═════╝  ╚═════╝    ╚═╝                                ║
║                                                          ║
║           Herramienta de Auditoría de Red                ║
║                    Versión 1.0.0                         ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""


class NetAuditBot:
    """
    Clase principal que orquesta el proceso completo de auditoría
    """
    
    def __init__(self, target: str, verbose: bool = False, generate_pdf: bool = False):
        """
        Inicializa NetAuditBot
        
        Args:
            target: Red o rango de IPs a auditar
            verbose: Modo verbose para más detalles
            generate_pdf: Generar reporte en formato PDF además de HTML
        """
        self.target = target
        self.verbose = verbose
        self.generate_pdf = generate_pdf
        self.start_time = time.time()
        
        # Resultados
        self.scan_results = None
        self.scan_summary = None
        self.analysis_results = None
        self.report_path = None
    
    def print_banner(self):
        """Muestra el banner de la aplicación"""
        print("\033[96m" + BANNER + "\033[0m")
        print(f"\n{'='*60}")
        print(f"  Red objetivo: {self.target}")
        print(f"  Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
    
    def run_scan(self) -> bool:
        """
        Ejecuta el escaneo de red
        
        Returns:
            True si el escaneo fue exitoso, False en caso contrario
        """
        try:
            print("\n🔍 FASE 1: ESCANEO DE RED")
            print("-" * 60)
            
            scanner = NetworkScanner(self.target)
            self.scan_results = scanner.scan_network()
            self.scan_summary = scanner.get_summary()
            
            if not self.scan_results:
                print("\n❌ No se encontraron hosts activos en la red especificada.")
                return False
            
            print(f"\n✅ Escaneo completado:")
            print(f"   • Hosts encontrados: {self.scan_summary['total_hosts']}")
            print(f"   • Puertos abiertos: {self.scan_summary['total_open_ports']}")
            print(f"   • Servicios únicos: {self.scan_summary['unique_services']}")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Error durante el escaneo: {str(e)}")
            return False
    
    def run_analysis(self) -> bool:
        """
        Ejecuta el análisis de seguridad
        
        Returns:
            True si el análisis fue exitoso, False en caso contrario
        """
        try:
            print("\n\n🔐 FASE 2: ANÁLISIS DE SEGURIDAD")
            print("-" * 60)
            
            # Verificar que hay resultados del escaneo
            if not self.scan_results:
                print("\n❌ No hay resultados de escaneo para analizar")
                return False
            
            analyzer = SecurityAnalyzer(self.scan_results)
            self.analysis_results = analyzer.analyze_all()
            
            # Mostrar resumen
            total_vulns = self.analysis_results['total_vulnerabilities']
            high_risk = self.analysis_results['by_risk']['ALTO']
            medium_risk = self.analysis_results['by_risk']['MEDIO']
            low_risk = self.analysis_results['by_risk']['BAJO']
            
            print(f"\n✅ Análisis completado:")
            print(f"   • Total vulnerabilidades: {total_vulns}")
            print(f"   • Riesgo ALTO: \033[91m{high_risk}\033[0m")
            print(f"   • Riesgo MEDIO: \033[93m{medium_risk}\033[0m")
            print(f"   • Riesgo BAJO: \033[92m{low_risk}\033[0m")
            
            # Mostrar alertas
            if high_risk > 0:
                print(f"\n⚠️  ALERTA: Se detectaron {high_risk} vulnerabilidades de ALTO riesgo")
            
            # Mostrar top vulnerabilidades si está en modo verbose
            if self.verbose and total_vulns > 0:
                print("\n📋 Top vulnerabilidades encontradas:")
                for i, vuln in enumerate(self.analysis_results['vulnerabilities'][:5], 1):
                    risk_color = {
                        'ALTO': '\033[91m',
                        'MEDIO': '\033[93m',
                        'BAJO': '\033[92m'
                    }.get(vuln['risk'], '')
                    print(f"   {i}. [{risk_color}{vuln['risk']}\033[0m] "
                          f"{vuln['host']} - {vuln['description']}")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Error durante el análisis: {str(e)}")
            return False
    
    def generate_report(self) -> bool:
        """
        Genera el reporte de auditoría
        
        Returns:
            True si el reporte fue generado exitosamente, False en caso contrario
        """
        try:
            print("\n\n📄 FASE 3: GENERACIÓN DE REPORTE")
            print("-" * 60)
            
            # Verificar que hay resultados
            if not self.scan_results or not self.analysis_results or not self.scan_summary:
                print("\n❌ Faltan datos para generar el reporte")
                return False
            
            generator = ReportGenerator(
                self.scan_results,
                self.analysis_results,
                self.scan_summary
            )
            
            self.report_path = generator.generate(self.generate_pdf)
            
            print(f"\n✅ Reporte generado exitosamente:")
            print(f"   📁 {self.report_path}")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Error generando el reporte: {str(e)}")
            return False
    
    def run(self) -> bool:
        """
        Ejecuta el proceso completo de auditoría
        
        Returns:
            True si todo el proceso fue exitoso, False en caso contrario
        """
        self.print_banner()
        
        # Fase 1: Escaneo
        if not self.run_scan():
            return False
        
        # Fase 2: Análisis
        if not self.run_analysis():
            return False
        
        # Fase 3: Reporte
        if not self.generate_report():
            return False
        
        # Resumen final
        elapsed_time = time.time() - self.start_time
        
        print("\n" + "=" * 60)
        print("✅ AUDITORÍA COMPLETADA EXITOSAMENTE")
        print("=" * 60)
        print(f"⏱️  Tiempo total: {elapsed_time:.2f} segundos")
        
        # Verificar que los datos existen antes de acceder
        if self.scan_summary:
            print(f"📊 Hosts analizados: {self.scan_summary['total_hosts']}")
        
        if self.analysis_results:
            print(f"🔍 Vulnerabilidades: {self.analysis_results['total_vulnerabilities']}")
        
        print(f"📄 Reporte: {self.report_path}")
        print("=" * 60)
        
        return True


def parse_arguments():
    """
    Parsea los argumentos de línea de comandos
    
    Returns:
        Namespace con los argumentos parseados
    """
    parser = argparse.ArgumentParser(
        description='NetAuditBot - Herramienta de Auditoría de Red Automatizada',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python netauditbot.py 192.168.1.0/24
  python netauditbot.py 192.168.1.100-120
  python netauditbot.py 10.0.0.1 -v
  
Nota: Se requiere Nmap instalado en el sistema.
        """
    )
    
    parser.add_argument(
        'target',
        help='Red o rango de IPs a auditar (ej: 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verbose - muestra información detallada'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )
    
    parser.add_argument(
        '--pdf',
        action='store_true',
        help='Generar reporte en formato PDF además de HTML'
    )
    
    return parser.parse_args()


def check_requirements():
    """
    Verifica que los requisitos estén instalados
    
    Returns:
        True si todos los requisitos están satisfechos, False en caso contrario
    """
    print("🔎 Verificando requisitos...")
    
    # Verificar Nmap
    try:
        import nmap
        nm = nmap.PortScanner()
        print("   ✓ Nmap instalado y accesible")
    except Exception as e:
        print("   ✗ Error: Nmap no está instalado o no es accesible")
        print(f"     {str(e)}")
        return False
    
    # Verificar librerías Python
    required_libs = [
        'jinja2',
        'matplotlib',
        'pandas'
    ]
    
    missing_libs = []
    for lib in required_libs:
        try:
            __import__(lib)
            print(f"   ✓ {lib} instalado")
        except ImportError:
            missing_libs.append(lib)
            print(f"   ✗ {lib} no encontrado")
    
    if missing_libs:
        print(f"\n❌ Faltan las siguientes librerías: {', '.join(missing_libs)}")
        print("   Instalar con: pip install " + " ".join(missing_libs))
        return False
    
    print("✅ Todos los requisitos están satisfechos\n")
    return True


def main():
    """
    Función principal
    """
    # Parsear argumentos
    args = parse_arguments()
    
    # Verificar requisitos
    if not check_requirements():
        sys.exit(1)
    
    # Verificar permisos (Nmap requiere privilegios en algunos casos)
    if os.name != 'nt' and os.geteuid() != 0:
        print("⚠️  Advertencia: Algunos escaneos pueden requerir privilegios de root/sudo")
        print("   Para mejores resultados, ejecutar con: sudo python netauditbot.py ...\n")
    
    # Ejecutar auditoría
    try:
        bot = NetAuditBot(args.target, args.verbose, args.pdf)
        success = bot.run()
        
        if success:
            print("\n💡 Consejo: Abra el reporte HTML en su navegador para ver los resultados completos\n")
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Auditoría interrumpida por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error fatal: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()