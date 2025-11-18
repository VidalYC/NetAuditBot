"""
NetAuditBot - Módulo de Generación de Reportes
Genera reportes HTML con gráficos y análisis
"""

import os
import logging
from datetime import datetime
from typing import Dict
import matplotlib
matplotlib.use('Agg')  # Backend sin GUI
import matplotlib.pyplot as plt
from jinja2 import Template
from config import *

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Clase para generar reportes de auditoría
    """
    
    def __init__(self, scan_results: Dict, analysis_results: Dict, scan_summary: Dict):
        """
        Inicializa el generador de reportes
        
        Args:
            scan_results: Resultados del escaneo
            analysis_results: Resultados del análisis de seguridad
            scan_summary: Resumen del escaneo
        """
        self.scan_results = scan_results
        self.analysis_results = analysis_results
        self.scan_summary = scan_summary
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.report_dir = os.path.join(REPORTS_DIR, f"report_{self.timestamp}")
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_charts(self) -> Dict[str, str]:
        """
        Genera gráficos para el reporte
        
        Returns:
            Diccionario con las rutas de los gráficos generados
        """
        logger.info("Generando gráficos...")
        charts = {}
        
        # Configurar estilo
        plt.style.use(CHART_STYLE)
        
        # 1. Gráfico de Distribución de Riesgos
        risk_data = self.analysis_results['by_risk']
        if sum(risk_data.values()) > 0:
            fig, ax = plt.subplots(figsize=(8, 6))
            colors = [RISK_COLORS['ALTO'], RISK_COLORS['MEDIO'], RISK_COLORS['BAJO']]
            bars = ax.bar(list(risk_data.keys()), list(risk_data.values()), color=colors)
            ax.set_title('Distribución de Vulnerabilidades por Nivel de Riesgo', fontsize=14, fontweight='bold')
            ax.set_ylabel('Cantidad')
            ax.set_xlabel('Nivel de Riesgo')
            
            # Agregar valores sobre las barras
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom')
            
            chart_path = os.path.join(self.report_dir, 'risk_distribution.png')
            plt.tight_layout()
            plt.savefig(chart_path, dpi=CHART_DPI)
            plt.close()
            charts['risk_distribution'] = chart_path
            logger.info("  ✓ Gráfico de riesgos generado")
        
        # 2. Gráfico de Tipos de Vulnerabilidades
        type_data = self.analysis_results['by_type']
        if sum(type_data.values()) > 0:
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.barh(list(type_data.keys()), list(type_data.values()), color='#5470c6')
            ax.set_title('Vulnerabilidades por Tipo', fontsize=14, fontweight='bold')
            ax.set_xlabel('Cantidad')
            
            chart_path = os.path.join(self.report_dir, 'vulnerability_types.png')
            plt.tight_layout()
            plt.savefig(chart_path, dpi=CHART_DPI)
            plt.close()
            charts['vulnerability_types'] = chart_path
            logger.info("  ✓ Gráfico de tipos generado")
        
        # 3. Gráfico de Puertos Abiertos por Host
        host_ports = {}
        for host_ip, host_data in self.scan_results.items():
            host_name = host_data.get('hostname', '') or host_ip
            host_ports[host_name[:20]] = host_data['open_ports_count']
        
        if host_ports:
            fig, ax = plt.subplots(figsize=(12, 6))
            bars = ax.bar(list(host_ports.keys()), list(host_ports.values()), color='#91cc75')
            ax.set_title('Puertos Abiertos por Host', fontsize=14, fontweight='bold')
            ax.set_ylabel('Número de Puertos')
            ax.set_xlabel('Host')
            plt.xticks(rotation=45, ha='right')
            
            # Línea de umbral seguro
            ax.axhline(y=MAX_SAFE_OPEN_PORTS, color='r', linestyle='--', 
                      label=f'Umbral Seguro ({MAX_SAFE_OPEN_PORTS})')
            ax.legend()
            
            chart_path = os.path.join(self.report_dir, 'open_ports.png')
            plt.tight_layout()
            plt.savefig(chart_path, dpi=CHART_DPI)
            plt.close()
            charts['open_ports'] = chart_path
            logger.info("  ✓ Gráfico de puertos generado")
        
        # 4. Gráfico de servicios más comunes
        services = {}
        for host_data in self.scan_results.values():
            for port in host_data['ports']:
                service = port['service']
                services[service] = services.get(service, 0) + 1
        
        if services:
            # Top 10 servicios
            top_services = dict(sorted(services.items(), key=lambda x: x[1], reverse=True)[:10])
            
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.barh(list(top_services.keys()), list(top_services.values()), color='#fac858')
            ax.set_title('Top 10 Servicios Detectados', fontsize=14, fontweight='bold')
            ax.set_xlabel('Cantidad de Instancias')
            
            chart_path = os.path.join(self.report_dir, 'top_services.png')
            plt.tight_layout()
            plt.savefig(chart_path, dpi=CHART_DPI)
            plt.close()
            charts['top_services'] = chart_path
            logger.info("  ✓ Gráfico de servicios generado")
        
        return charts
    
    def generate_html_report(self, charts: Dict[str, str]) -> str:
        """
        Genera el reporte HTML completo
        
        Returns:
            Ruta del archivo HTML generado
        """
        logger.info("Generando reporte HTML...")
        
        # Template HTML
        html_template = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }
        
        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }
        
        .summary-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2a5298;
        }
        
        .section {
            padding: 40px;
        }
        
        .section h2 {
            color: #2a5298;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            font-size: 1.8em;
        }
        
        .chart-container {
            margin: 30px 0;
            text-align: center;
        }
        
        .chart-container img {
            max-width: 100%;
            height: auto;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-radius: 10px;
            overflow: hidden;
        }
        
        thead {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        th, td {
            padding: 15px;
            text-align: left;
        }
        
        th {
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
        }
        
        tbody tr {
            border-bottom: 1px solid #eee;
            transition: background 0.3s;
        }
        
        tbody tr:hover {
            background: #f8f9fa;
        }
        
        .risk-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            display: inline-block;
        }
        
        .risk-ALTO {
            background: #dc3545;
            color: white;
        }
        
        .risk-MEDIO {
            background: #ffc107;
            color: #000;
        }
        
        .risk-BAJO {
            background: #28a745;
            color: white;
        }
        
        .footer {
            background: #2a2a2a;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        
        .alert {
            padding: 20px;
            margin: 20px 0;
            border-radius: 10px;
            border-left: 5px solid;
        }
        
        .alert-danger {
            background: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }
        
        .alert-warning {
            background: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }
        
        .alert-success {
            background: #d4edda;
            border-color: #28a745;
            color: #155724;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ {{ title }}</h1>
            <p class="subtitle">{{ project_name }} v{{ version }}</p>
            <p class="subtitle">{{ scan_date }}</p>
        </div>
        
        <!-- Summary Cards -->
        <div class="summary">
            <div class="summary-card">
                <h3>Hosts Escaneados</h3>
                <div class="value">{{ total_hosts }}</div>
            </div>
            <div class="summary-card">
                <h3>Puertos Abiertos</h3>
                <div class="value">{{ total_ports }}</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilidades</h3>
                <div class="value" style="color: #dc3545;">{{ total_vulns }}</div>
            </div>
            <div class="summary-card">
                <h3>Riesgo Alto</h3>
                <div class="value" style="color: #dc3545;">{{ high_risk }}</div>
            </div>
        </div>
        
        <!-- Resumen Ejecutivo -->
        <div class="section">
            <h2>📊 Resumen Ejecutivo</h2>
            
            {% if total_vulns > 0 %}
                {% if high_risk > 0 %}
                <div class="alert alert-danger">
                    <strong>⚠️ ALERTA CRÍTICA:</strong> Se detectaron {{ high_risk }} vulnerabilidades de ALTO riesgo que requieren atención inmediata.
                </div>
                {% elif medium_risk > 0 %}
                <div class="alert alert-warning">
                    <strong>⚠️ ATENCIÓN:</strong> Se detectaron {{ medium_risk }} vulnerabilidades de MEDIO riesgo que deben ser revisadas.
                </div>
                {% endif %}
            {% else %}
                <div class="alert alert-success">
                    <strong>✅ EXCELENTE:</strong> No se detectaron vulnerabilidades críticas en el escaneo.
                </div>
            {% endif %}
            
            <p style="margin-top: 20px; line-height: 1.8;">
                El escaneo de la red <strong>{{ target }}</strong> ha identificado <strong>{{ total_hosts }}</strong> 
                host(s) activo(s) con un total de <strong>{{ total_ports }}</strong> puertos abiertos. 
                El análisis de seguridad detectó <strong>{{ total_vulns }}</strong> vulnerabilidad(es) potencial(es).
            </p>
        </div>
        
        <!-- Gráficos -->
        {% if charts %}
        <div class="section" style="background: #f8f9fa;">
            <h2>📈 Análisis Visual</h2>
            
            {% for chart_name, chart_path in charts.items() %}
            <div class="chart-container">
                <img src="file://{{ chart_path }}" alt="{{ chart_name }}">
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        <!-- Tabla de Hosts -->
        <div class="section">
            <h2>💻 Hosts Detectados</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Hostname</th>
                        <th>Sistema Operativo</th>
                        <th>Puertos Abiertos</th>
                        <th>Estado</th>
                    </tr>
                </thead>
                <tbody>
                    {% for host_ip, host_data in hosts.items() %}
                    <tr>
                        <td><strong>{{ host_ip }}</strong></td>
                        <td>{{ host_data.hostname or 'N/A' }}</td>
                        <td>{{ host_data.os or 'Desconocido' }}</td>
                        <td>{{ host_data.open_ports_count }}</td>
                        <td>
                            {% if host_data.open_ports_count > max_safe_ports %}
                                <span class="risk-badge risk-MEDIO">⚠️ Revisar</span>
                            {% else %}
                                <span class="risk-badge risk-BAJO">✓ OK</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <!-- Tabla de Vulnerabilidades -->
        {% if vulnerabilities %}
        <div class="section">
            <h2>🔴 Vulnerabilidades Detectadas</h2>
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Tipo</th>
                        <th>Puerto</th>
                        <th>Servicio</th>
                        <th>Riesgo</th>
                        <th>Descripción</th>
                        <th>Recomendación</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vuln in vulnerabilities %}
                    <tr>
                        <td><strong>{{ vuln.host }}</strong></td>
                        <td>{{ vuln.type }}</td>
                        <td>{{ vuln.port }}</td>
                        <td>{{ vuln.service }}</td>
                        <td><span class="risk-badge risk-{{ vuln.risk }}">{{ vuln.risk }}</span></td>
                        <td>{{ vuln.description }}</td>
                        <td><small>{{ vuln.recommendation }}</small></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
        
        <!-- Recomendaciones -->
        <div class="section" style="background: #f8f9fa;">
            <h2>💡 Recomendaciones Generales</h2>
            <ul style="line-height: 2; list-style-position: inside;">
                <li>✓ Cerrar todos los puertos innecesarios y aplicar el principio de mínimo privilegio</li>
                <li>✓ Actualizar todos los servicios a las versiones más recientes y con parches de seguridad</li>
                <li>✓ Implementar cifrado en todos los servicios que transmiten información sensible</li>
                <li>✓ Configurar firewalls y segmentación de red adecuada</li>
                <li>✓ Implementar sistemas de detección y prevención de intrusiones (IDS/IPS)</li>
                <li>✓ Realizar auditorías de seguridad periódicas</li>
                <li>✓ Mantener un inventario actualizado de todos los activos de red</li>
            </ul>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generado por <strong>{{ project_name }}</strong> v{{ version }}</p>
            <p>{{ author }} | {{ scan_date }}</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Preparar datos para el template
        template_data = {
            'title': REPORT_TITLE,
            'project_name': PROJECT_NAME,
            'version': VERSION,
            'author': AUTHOR,
            'scan_date': self.scan_summary['scan_date'],
            'target': self.scan_summary['target'],
            'total_hosts': self.scan_summary['total_hosts'],
            'total_ports': self.scan_summary['total_open_ports'],
            'total_vulns': self.analysis_results['total_vulnerabilities'],
            'high_risk': self.analysis_results['by_risk']['ALTO'],
            'medium_risk': self.analysis_results['by_risk']['MEDIO'],
            'low_risk': self.analysis_results['by_risk']['BAJO'],
            'hosts': self.scan_results,
            'vulnerabilities': self.analysis_results['vulnerabilities'],
            'charts': charts,
            'max_safe_ports': MAX_SAFE_OPEN_PORTS
        }
        
        # Renderizar template
        template = Template(html_template)
        html_content = template.render(**template_data)
        
        # Guardar archivo HTML
        report_filename = f"{REPORT_FILENAME_PREFIX}_{self.timestamp}.html"
        report_path = os.path.join(self.report_dir, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"✓ Reporte HTML generado: {report_path}")
        return report_path
    
    def generate(self, generate_pdf: bool = False) -> Dict[str, str]:
        """
        Genera el reporte completo
        
        Args:
            generate_pdf: Si es True, también genera versión PDF
        
        Returns:
            Diccionario con rutas de los reportes generados
        """
        logger.info(MESSAGES["report_generated"])
        
        reports = {}
        
        # Generar HTML
        charts = self.generate_charts()
        html_path = self.generate_html_report(charts)
        reports['html'] = html_path
        
        # Generar PDF si se solicita
        if generate_pdf:
            try:
                from pdf_generator import PDFReportGenerator
                
                logger.info("Generando reporte PDF...")
                
                pdf_gen = PDFReportGenerator(
                    self.scan_results,
                    self.analysis_results,
                    self.scan_summary,
                    charts  # Reutilizar los gráficos ya generados
                )
                
                pdf_path = pdf_gen.generate_pdf()
                reports['pdf'] = pdf_path
                
            except ImportError:
                logger.warning("⚠️  reportlab no está instalado. Instala con: pip install reportlab")
                print("\n⚠️  Para generar PDF instala: pip install reportlab")
            except Exception as e:
                logger.error(f"Error generando PDF: {e}")
                print(f"\n⚠️  Error generando PDF: {e}")
        
        return reports


if __name__ == "__main__":
    print("Módulo de generación de reportes cargado correctamente")