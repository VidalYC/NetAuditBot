"""
NetAuditBot - Módulo de Generación de Reportes
Genera reportes HTML con gráficos y análisis - Versión Dashboard Profesional
"""

import os
import logging
from datetime import datetime
import base64
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
        Genera el reporte HTML completo con diseño profesional tipo dashboard
        
        Returns:
            Ruta del archivo HTML generado
        """
        logger.info("Generando reporte HTML...")
        
        # Convertir imágenes a Base64 para embeberlas
        charts_base64 = {}
        for name, path in charts.items():
            try:
                with open(path, "rb") as image_file:
                    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                    charts_base64[name] = encoded_string
            except Exception as e:
                logger.error(f"No se pudo codificar la imagen {path} a Base64: {e}")
                charts_base64[name] = None
        
        # Template HTML Mejorado - Estilo Dashboard Profesional
        html_template = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary-color: #2d3748;
            --secondary-color: #4a5568;
            --success-color: #48bb78;
            --warning-color: #ed8936;
            --danger-color: #f56565;
            --dark-bg: #1a202c;
            --card-bg: #ffffff;
            --text-primary: #2d3748;
            --text-secondary: #718096;
            --border-color: #e2e8f0;
            --accent-green: #38a169;
            --light-gray: #f7fafc;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 50%, #2563eb 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            padding: 0;
            margin: 0;
        }
        
        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px;
        }
        
        /* Header con diseño moderno */
        .dashboard-header {
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            border-radius: 16px;
            padding: 50px 40px;
            margin-bottom: 30px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            color: white;
            position: relative;
            overflow: hidden;
            text-align: center;
        }
        
        .dashboard-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg"><defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="1"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }
        
        .header-content {
            position: relative;
            z-index: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        
        .header-title {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .header-logo {
            font-size: 5em;
            animation: pulse 2s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .header-title h1 {
            font-size: 2.5em;
            font-weight: 800;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .header-meta {
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            margin-top: 20px;
            font-size: 0.95em;
            opacity: 0.95;
            justify-content: center;
        }
        
        .header-meta-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        /* KPI Cards - Tarjetas de métricas principales */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }
        
        .kpi-card {
            background: rgb(236, 236, 236);
            border-radius: 16px;
            padding: 30px;
            box-shadow: rgba(0, 0, 0, 0.4) 0px 2px 4px, rgba(0, 0, 0, 0.3) 0px 7px 13px -3px, rgba(0, 0, 0, 0.2) 0px -3px 0px inset;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .kpi-card:hover {
            transform: translateY(-5px);
            box-shadow: rgba(0, 0, 0, 0.5) 0px 4px 8px, rgba(0, 0, 0, 0.4) 0px 10px 20px -3px, rgba(0, 0, 0, 0.2) 0px -3px 0px inset;
        }
        
        .kpi-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(180deg, var(--accent-color), transparent);
        }
        
        .kpi-card.primary { --accent-color: #2d3748; }
        .kpi-card.success { --accent-color: var(--accent-green); }
        .kpi-card.danger { --accent-color: var(--danger-color); }
        .kpi-card.warning { --accent-color: var(--warning-color); }
        
        .kpi-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }
        
        .kpi-title {
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
        }
        
        .kpi-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.8em;
            background: var(--accent-color);
            color: white;
            opacity: 1;
        }
        
        .kpi-value {
            font-size: 3em;
            font-weight: 800;
            color: var(--accent-color);
            line-height: 1;
            margin-bottom: 8px;
        }
        
        .kpi-description {
            font-size: 0.9em;
            color: var(--text-secondary);
        }
        
        /* Dashboard Grid Layout */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 25px;
        }
        
        .dashboard-card {
            background: rgb(236, 236, 236);
            border-radius: 16px;
            padding: 30px;
            box-shadow: rgba(0, 0, 0, 0.4) 0px 2px 4px, rgba(0, 0, 0, 0.3) 0px 7px 13px -3px, rgba(0, 0, 0, 0.2) 0px -3px 0px inset;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .dashboard-card:hover {
            transform: translateY(-2px);
            box-shadow: rgba(0, 0, 0, 0.5) 0px 4px 8px, rgba(0, 0, 0, 0.4) 0px 10px 20px -3px, rgba(0, 0, 0, 0.2) 0px -3px 0px inset;
        }
        
        /* Responsive Grid */
        .col-12 { grid-column: span 12; }
        .col-8 { grid-column: span 8; }
        .col-6 { grid-column: span 6; }
        .col-4 { grid-column: span 4; }
        
        @media (max-width: 1200px) {
            .col-8, .col-6, .col-4 { grid-column: span 12; }
        }
        
        /* Card Headers */
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--border-color);
        }
        
        .card-title {
            font-size: 1.4em;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-badge {
            font-size: 0.75em;
            padding: 6px 14px;
            border-radius: 8px;
            font-weight: 600;
            background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
            color: white;
        }
        
        /* Alerts Mejoradas */
        .alert {
            padding: 20px 25px;
            border-radius: 12px;
            margin-bottom: 25px;
            display: flex;
            align-items: flex-start;
            gap: 15px;
            border-left: 4px solid;
            font-size: 0.95em;
            line-height: 1.6;
        }
        
        .alert-icon {
            font-size: 1.5em;
            flex-shrink: 0;
        }
        
        .alert-danger {
            background: #fed7d7;
            border-color: var(--danger-color);
            color: #742a2a;
        }
        
        .alert-warning {
            background: #feebc8;
            border-color: var(--warning-color);
            color: #7c2d12;
        }
        
        .alert-success {
            background: #c6f6d5;
            border-color: var(--accent-green);
            color: #22543d;
        }
        
        .alert strong {
            font-weight: 700;
            display: block;
            margin-bottom: 5px;
        }
        
        /* Tablas Modernas */
        .table-container {
            overflow-x: auto;
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: rgb(236, 236, 236);
        }
        
        thead {
            background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
            color: white;
        }
        
        th {
            padding: 16px 20px;
            text-align: left;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: white;
            border-bottom: 2px solid var(--border-color);
        }
        
        td {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9em;
        }
        
        tbody tr {
            transition: background 0.2s ease;
        }
        
        tbody tr:hover {
            background: #f7fafc;
        }
        
        tbody tr:last-child td {
            border-bottom: none;
        }
        
        /* Risk Badges Mejorados */
        .risk-badge {
            padding: 6px 14px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.8em;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        
        .risk-ALTO {
            background: linear-gradient(135deg, #f56565, #e53e3e);
            color: white;
            box-shadow: 0 4px 12px rgba(245, 101, 101, 0.4);
        }
        
        .risk-MEDIO {
            background: linear-gradient(135deg, #ed8936, #dd6b20);
            color: white;
            box-shadow: 0 4px 12px rgba(237, 137, 54, 0.4);
        }
        
        .risk-BAJO {
            background: linear-gradient(135deg, var(--accent-green), #2f855a);
            color: white;
            box-shadow: 0 4px 12px rgba(56, 161, 105, 0.4);
        }
        
        .status-ok {
            background: linear-gradient(135deg, var(--accent-green), #2f855a);
            color: white;
        }
        
        .status-warning {
            background: linear-gradient(135deg, #ed8936, #dd6b20);
            color: white;
        }
        
        /* Gráficos */
        .chart-container {
            margin: 25px 0;
            text-align: center;
            background: #f7fafc;
            padding: 25px;
            border-radius: 12px;
        }
        
        .chart-container img {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
        }
        
        /* Lista de Recomendaciones con Dropdown */
        .recommendations-dropdown {
            border: 1px solid var(--border-color);
            background: rgb(236, 236, 236);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: rgba(0, 0, 0, 0.4) 0px 2px 4px, rgba(0, 0, 0, 0.3) 0px 7px 13px -3px, rgba(0, 0, 0, 0.2) 0px -3px 0px inset;
        }
        
        .recommendations-header {
            padding: 20px;
            background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            color: white;
        }
        
        .recommendations-header:hover {
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
        }
        
        .recommendations-title {
            font-weight: 600;
            font-size: 1.1em;
        }
        
        .recommendations-toggle {
            font-size: 1.5em;
            transition: transform 0.3s ease;
        }
        
        .recommendations-toggle.active {
            transform: rotate(180deg);
        }
        
        .recommendations-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        
        .recommendations-content.active {
            max-height: 1000px;
        }
        
        .recommendations-list {
            list-style: none;
            padding: 20px;
        }
        
        .recommendations-list li {
            padding: 15px 20px;
            margin-bottom: 12px;
            background: #f7fafc;
            border-left: 4px solid var(--accent-green);
            border-radius: 8px;
            display: flex;
            align-items: flex-start;
            gap: 15px;
        }
        
        .recommendations-list li::before {
            content: '✓';
            color: var(--accent-green);
            font-weight: bold;
            font-size: 1.2em;
            flex-shrink: 0;
        }
        
        /* Footer Mejorado */
        .dashboard-footer {
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            border-radius: 16px;
            padding: 30px;
            text-align: center;
            color: #cbd5e1;
            margin-top: 30px;
            box-shadow: 0 -10px 30px rgba(0, 0, 0, 0.2);
        }
        
        .footer-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .footer-brand {
            font-weight: 700;
            font-size: 1.1em;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .footer-info {
            font-size: 0.9em;
        }
        
        /* Scrollbar personalizado */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 6px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.3);
            border-radius: 6px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.5);
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .dashboard-container {
                padding: 15px;
            }
            
            .dashboard-header {
                padding: 30px 20px;
                border-radius: 12px;
            }
            
            .header-title h1 {
                font-size: 1.8em;
            }
            
            .kpi-grid {
                grid-template-columns: 1fr;
            }
            
            .kpi-value {
                font-size: 2.5em;
            }
            
            .dashboard-card {
                padding: 20px;
                border-radius: 12px;
            }
            
            .footer-content {
                flex-direction: column;
                text-align: center;
            }
            
            /* Gráficas en una columna en móvil */
            .charts-grid {
                grid-template-columns: 1fr !important;
            }
        }
        
        /* Grid de gráficas */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 30px;
        }
        
        /* Print Styles */
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .dashboard-container {
                max-width: 100%;
                padding: 0;
            }
            
            .dashboard-header {
                background: #1e3c72 !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            
            .dashboard-card {
                break-inside: avoid;
                page-break-inside: avoid;
            }
        }
    </style>
    <script>
        // Script para el dropdown de recomendaciones
        document.addEventListener('DOMContentLoaded', function() {
            const recommendationsHeader = document.querySelector('.recommendations-header');
            const recommendationsContent = document.querySelector('.recommendations-content');
            const recommendationsToggle = document.querySelector('.recommendations-toggle');
            
            if (recommendationsHeader) {
                recommendationsHeader.addEventListener('click', function() {
                    recommendationsContent.classList.toggle('active');
                    recommendationsToggle.classList.toggle('active');
                });
            }
        });
    </script>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <div class="dashboard-header">
            <div class="header-content">
                <div class="header-title">
                    <div class="header-logo">🛡️</div>
                    <div>
                        <h1>{{ title }}</h1>
                        <p style="opacity: 0.9; margin-top: 5px;">{{ project_name }} v{{ version }}</p>
                    </div>
                </div>
                <div class="header-meta">
                    <div class="header-meta-item">
                        <span>📅</span>
                        <span>{{ scan_date }}</span>
                    </div>
                    <div class="header-meta-item">
                        <span>🎯</span>
                        <span>Target: {{ target }}</span>
                    </div>
                    <div class="header-meta-item">
                        <span>👤</span>
                        <span>{{ author }}</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- KPI Cards -->
        <div class="kpi-grid">
            <div class="kpi-card primary">
                <div class="kpi-header">
                    <div class="kpi-title">Hosts Escaneados</div>
                    <div class="kpi-icon">💻</div>
                </div>
                <div class="kpi-value">{{ total_hosts }}</div>
                <div class="kpi-description">Dispositivos detectados en la red</div>
            </div>
            
            <div class="kpi-card success">
                <div class="kpi-header">
                    <div class="kpi-title">Puertos Abiertos</div>
                    <div class="kpi-icon">🔌</div>
                </div>
                <div class="kpi-value">{{ total_ports }}</div>
                <div class="kpi-description">Servicios expuestos totales</div>
            </div>
            
            <div class="kpi-card danger">
                <div class="kpi-header">
                    <div class="kpi-title">Vulnerabilidades</div>
                    <div class="kpi-icon">⚠️</div>
                </div>
                <div class="kpi-value">{{ total_vulns }}</div>
                <div class="kpi-description">Problemas de seguridad detectados</div>
            </div>
            
            <div class="kpi-card danger">
                <div class="kpi-header">
                    <div class="kpi-title">Riesgo Alto</div>
                    <div class="kpi-icon">🔴</div>
                </div>
                <div class="kpi-value">{{ high_risk }}</div>
                <div class="kpi-description">Requieren atención inmediata</div>
            </div>
        </div>
        
        <!-- Dashboard Grid -->
        <div class="dashboard-grid">
            <!-- Resumen Ejecutivo -->
            <div class="dashboard-card col-12">
                <div class="card-header">
                    <h2 class="card-title">Resumen Ejecutivo</h2>
                    <span class="card-badge">Overview</span>
                </div>
                
                {% if total_vulns > 0 %}
                    {% if high_risk > 0 %}
                    <div class="alert alert-danger">
                        <span class="alert-icon">🚨</span>
                        <div>
                            <strong>ALERTA CRÍTICA</strong>
                            Se detectaron {{ high_risk }} vulnerabilidades de ALTO riesgo que requieren atención inmediata.
                        </div>
                    </div>
                    {% elif medium_risk > 0 %}
                    <div class="alert alert-warning">
                        <span class="alert-icon">⚠️</span>
                        <div>
                            <strong>ATENCIÓN REQUERIDA</strong>
                            Se detectaron {{ medium_risk }} vulnerabilidades de MEDIO riesgo que deben ser revisadas.
                        </div>
                    </div>
                    {% endif %}
                {% else %}
                    <div class="alert alert-success">
                        <span class="alert-icon">✅</span>
                        <div>
                            <strong>ESTADO ÓPTIMO</strong>
                            No se detectaron vulnerabilidades críticas en el escaneo realizado.
                        </div>
                    </div>
                {% endif %}
                
                <p style="margin-top: 20px; line-height: 1.8; color: var(--text-secondary);">
                    El escaneo exhaustivo de la red <strong style="color: var(--primary-color);">{{ target }}</strong> ha identificado 
                    <strong>{{ total_hosts }}</strong> host(s) activo(s) con un total de <strong>{{ total_ports }}</strong> puertos abiertos. 
                    El análisis de seguridad automatizado detectó <strong>{{ total_vulns }}</strong> vulnerabilidad(es) potencial(es) 
                    que requieren evaluación.
                </p>
            </div>
            
            <!-- Gráficos de Análisis -->
            <div class="dashboard-card col-12">
                <div class="card-header">
                    <h2 class="card-title">Análisis Gráfico</h2>
                    <span class="card-badge">Visualización de Datos</span>
                </div>
                
                <div class="charts-grid">
                    {% if charts_base64['risk_distribution'] %}
                    <div class="chart-container">
                        <h3 style="margin-bottom: 15px; color: var(--text-primary); font-size: 1.1em;">Distribución de Riesgos</h3>
                        <img src="data:image/png;base64,{{ charts_base64['risk_distribution'] }}" alt="Distribución de Riesgos">
                    </div>
                    {% endif %}
                    
                    {% if charts_base64['vulnerability_types'] %}
                    <div class="chart-container">
                        <h3 style="margin-bottom: 15px; color: var(--text-primary); font-size: 1.1em;">Tipos de Vulnerabilidades</h3>
                        <img src="data:image/png;base64,{{ charts_base64['vulnerability_types'] }}" alt="Tipos de Vulnerabilidades">
                    </div>
                    {% endif %}
                    
                    {% if charts_base64['open_ports'] %}
                    <div class="chart-container">
                        <h3 style="margin-bottom: 15px; color: var(--text-primary); font-size: 1.1em;">Puertos Abiertos por Host</h3>
                        <img src="data:image/png;base64,{{ charts_base64['open_ports'] }}" alt="Puertos Abiertos">
                    </div>
                    {% endif %}
                    
                    {% if charts_base64['top_services'] %}
                    <div class="chart-container">
                        <h3 style="margin-bottom: 15px; color: var(--text-primary); font-size: 1.1em;">Servicios Más Comunes</h3>
                        <img src="data:image/png;base64,{{ charts_base64['top_services'] }}" alt="Top Servicios">
                    </div>
                    {% endif %}
                </div>
            </div>
            
            <!-- Tabla de Vulnerabilidades -->
            {% if vulnerabilities %}
            <div class="dashboard-card col-12">
                <div class="card-header">
                    <h2 class="card-title">Vulnerabilidades Detectadas</h2>
                    <span class="card-badge">{{ vulnerabilities|length }} items</span>
                </div>
                
                <div class="table-container">
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
                                <td><span style="color: var(--text-secondary);">{{ vuln.type }}</span></td>
                                <td><code style="background: #f1f5f9; padding: 4px 8px; border-radius: 4px;">{{ vuln.port }}</code></td>
                                <td>{{ vuln.service }}</td>
                                <td><span class="risk-badge risk-{{ vuln.risk }}">{{ vuln.risk }}</span></td>
                                <td style="max-width: 300px;">{{ vuln.description }}</td>
                                <td style="max-width: 300px; font-size: 0.85em; color: var(--text-secondary);">{{ vuln.recommendation }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endif %}
            
            <!-- Tabla de Hosts -->
            <div class="dashboard-card col-12">
                <div class="card-header">
                    <h2 class="card-title">Inventario de Hosts</h2>
                    <span class="card-badge">{{ hosts|length }} dispositivos</span>
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Dirección IP</th>
                                <th>Hostname</th>
                                <th>Sistema Operativo</th>
                                <th>Puertos Abiertos</th>
                                <th>Estado de Seguridad</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for host_ip, host_data in hosts.items() %}
                            <tr>
                                <td><code style="background: #f1f5f9; padding: 4px 8px; border-radius: 4px; font-weight: 600;">{{ host_ip }}</code></td>
                                <td>{{ host_data.hostname or '<em style="color: var(--text-secondary);">N/A</em>' }}</td>
                                <td>{{ host_data.os or '<em style="color: var(--text-secondary);">Desconocido</em>' }}</td>
                                <td><strong style="color: var(--primary-color);">{{ host_data.open_ports_count }}</strong></td>
                                <td>
                                    {% if host_data.open_ports_count > max_safe_ports %}
                                        <span class="risk-badge status-warning">⚠️ Revisar</span>
                                    {% else %}
                                        <span class="risk-badge status-ok">✓ OK</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Recomendaciones de Seguridad con Dropdown -->
            <div class="dashboard-card col-12">
                <div class="card-header">
                    <h2 class="card-title">Recomendaciones de Seguridad</h2>
                    <span class="card-badge">Best Practices</span>
                </div>
                
                <div class="recommendations-dropdown">
                    <div class="recommendations-header">
                        <span class="recommendations-title">Ver Recomendaciones (10)</span>
                        <span class="recommendations-toggle">▼</span>
                    </div>
                    <div class="recommendations-content">
                        <ul class="recommendations-list">
                            <li>
                                <span>Cerrar todos los puertos innecesarios y aplicar el principio de mínimo privilegio en todos los servicios expuestos.</span>
                            </li>
                            <li>
                                <span>Actualizar todos los servicios a las versiones más recientes con los últimos parches de seguridad aplicados.</span>
                            </li>
                            <li>
                                <span>Implementar cifrado TLS/SSL en todos los servicios que transmiten información sensible (HTTPS, SFTP, FTPS).</span>
                            </li>
                            <li>
                                <span>Configurar firewalls perimetrales y segmentación de red adecuada para limitar la superficie de ataque.</span>
                            </li>
                            <li>
                                <span>Implementar sistemas de detección y prevención de intrusiones (IDS/IPS) con reglas actualizadas.</span>
                            </li>
                            <li>
                                <span>Establecer un programa de auditorías de seguridad periódicas para monitorización continua.</span>
                            </li>
                            <li>
                                <span>Mantener un inventario actualizado de todos los activos de red y sus configuraciones de seguridad.</span>
                            </li>
                            <li>
                                <span>Implementar autenticación multifactor (MFA) en todos los servicios críticos que lo soporten.</span>
                            </li>
                            <li>
                                <span>Configurar logging centralizado y monitoreo activo de eventos de seguridad (SIEM).</span>
                            </li>
                            <li>
                                <span>Establecer políticas de respuesta a incidentes y realizar simulacros periódicos.</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="dashboard-footer">
            <div class="footer-content">
                <div class="footer-brand">
                    🛡️ {{ project_name }} v{{ version }}
                </div>
                <div class="footer-info">
                    Generado el {{ scan_date }} | {{ author }}
                </div>
                <div class="footer-info">
                    Reporte de Auditoría de Seguridad de Red
                </div>
            </div>
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
            'charts_base64': charts_base64,
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