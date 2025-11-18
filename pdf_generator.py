"""
NetAuditBot - Módulo de Generación de Reportes PDF
Genera reportes en formato PDF
"""

import os
import logging
from datetime import datetime
from typing import Dict
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from config import *

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """
    Clase para generar reportes PDF de auditoría
    """
    
    def __init__(self, scan_results: Dict, analysis_results: Dict, scan_summary: Dict, charts: Dict):
        """
        Inicializa el generador de PDF
        
        Args:
            scan_results: Resultados del escaneo
            analysis_results: Resultados del análisis de seguridad
            scan_summary: Resumen del escaneo
            charts: Rutas de los gráficos generados
        """
        self.scan_results = scan_results
        self.analysis_results = analysis_results
        self.scan_summary = scan_summary
        self.charts = charts
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.report_dir = os.path.join(REPORTS_DIR, f"report_{self.timestamp}")
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Configurar estilos
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Configura estilos personalizados para el PDF"""
        # Título principal
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e3c72'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtítulos
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2a5298'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Texto normal
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=10
        ))
        
        # Alertas
        self.styles.add(ParagraphStyle(
            name='Alert',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#721c24'),
            backColor=colors.HexColor('#f8d7da'),
            borderColor=colors.HexColor('#dc3545'),
            borderWidth=1,
            borderPadding=10,
            spaceAfter=12
        ))
    
    def _create_header(self, story):
        """Crea el encabezado del reporte"""
        # Título
        title = Paragraph(
            f"<b>{REPORT_TITLE}</b><br/><font size=12>{PROJECT_NAME} v{VERSION}</font>",
            self.styles['CustomTitle']
        )
        story.append(title)
        story.append(Spacer(1, 0.2*inch))
        
        # Información del escaneo
        info_data = [
            ['Red Objetivo:', self.scan_summary['target']],
            ['Fecha:', self.scan_summary['scan_date']],
            ['Generado por:', f"{AUTHOR}"]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(info_table)
        story.append(Spacer(1, 0.3*inch))
    
    def _create_executive_summary(self, story):
        """Crea el resumen ejecutivo"""
        story.append(Paragraph("Resumen Ejecutivo", self.styles['CustomHeading']))
        
        # Estadísticas principales
        stats_data = [
            ['Métrica', 'Valor'],
            ['Hosts Escaneados', str(self.scan_summary['total_hosts'])],
            ['Puertos Abiertos', str(self.scan_summary['total_open_ports'])],
            ['Servicios Únicos', str(self.scan_summary['unique_services'])],
            ['Total Vulnerabilidades', str(self.analysis_results['total_vulnerabilities'])],
            ['Vulnerabilidades ALTO', str(self.analysis_results['by_risk']['ALTO'])],
            ['Vulnerabilidades MEDIO', str(self.analysis_results['by_risk']['MEDIO'])],
            ['Vulnerabilidades BAJO', str(self.analysis_results['by_risk']['BAJO'])]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Párrafo descriptivo del resumen
        total_vulns = self.analysis_results['total_vulnerabilities']
        summary_text = f"""
        El análisis de la red <b>{self.scan_summary['target']}</b> ha concluido. Se escanearon un total de 
        <b>{self.scan_summary['total_hosts']}</b> host(s), identificando <b>{total_vulns}</b> 
        vulnerabilidad(es) en total.
        """
        
        if total_vulns > 0:
            summary_text += """
            Los resultados indican la presencia de riesgos de seguridad que deben ser atendidos. A continuación se presenta un desglose detallado de los hallazgos.
            """
        else:
            summary_text += """
            <b>Felicitaciones:</b> No se encontraron vulnerabilidades conocidas durante este análisis, lo que sugiere una buena postura de seguridad en la red.
            """
        story.append(Paragraph(summary_text, self.styles['CustomBody']))
        
        # Alerta de riesgo alto
        high_risk = self.analysis_results['by_risk']['ALTO']
        if high_risk > 0:
            alert_text = f"<b>ALERTA CRÍTICA:</b> Se detectaron {high_risk} vulnerabilidades de ALTO riesgo que requieren atención inmediata."
            story.append(Paragraph(alert_text, self.styles['Alert']))
        
        story.append(Spacer(1, 0.3*inch))
    
    def _add_charts(self, story):
        """Añade los gráficos al reporte"""
        story.append(Paragraph("Análisis Visual", self.styles['CustomHeading']))
        
        intro_text = """
        La siguiente sección proporciona una representación visual de los resultados de la auditoría.
        Estos gráficos ayudan a identificar rápidamente las áreas clave de preocupación y la distribución de los riesgos.
        """
        story.append(Paragraph(intro_text, self.styles['CustomBody']))
        
        for chart_name, chart_path in self.charts.items():
            if os.path.exists(chart_path):
                try:
                    img = Image(chart_path, width=5*inch, height=3*inch)
                    story.append(img)
                    story.append(Spacer(1, 0.2*inch))
                except Exception as e:
                    logger.error(f"Error añadiendo gráfico {chart_name}: {e}")
        
        story.append(Spacer(1, 0.2*inch))
    
    def _create_hosts_table(self, story):
        """Crea la tabla de hosts detectados"""
        story.append(PageBreak())
        story.append(Paragraph("Hosts Detectados", self.styles['CustomHeading']))
        
        intro_text = """
        La siguiente tabla enumera todos los hosts activos que se descubrieron en la red durante la fase de escaneo.
        Para cada host, se muestra su dirección IP, nombre de host (si está disponible), sistema operativo detectado y el número total de puertos abiertos.
        """
        story.append(Paragraph(intro_text, self.styles['CustomBody']))
        
        # Datos de la tabla
        table_data = [['IP', 'Hostname', 'SO', 'Puertos', 'Estado']]
        
        for host_ip, host_data in self.scan_results.items():
            hostname = host_data.get('hostname', 'N/A') or 'N/A'
            os_info = host_data.get('os', 'Desconocido') or 'Desconocido'
            ports_count = host_data.get('open_ports_count', 0)
            
            # Determinar estado
            if ports_count > MAX_SAFE_OPEN_PORTS:
                estado = 'REVISAR'
            else:
                estado = 'OK'
            
            table_data.append([
                host_ip,
                hostname[:20],
                os_info[:30],
                str(ports_count),
                estado
            ])
        
        # Crear tabla
        hosts_table = Table(table_data, colWidths=[1.5*inch, 1.5*inch, 2*inch, 0.8*inch, 0.8*inch])
        hosts_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        
        story.append(hosts_table)
        story.append(Spacer(1, 0.3*inch))
    
    def _create_vulnerabilities_table(self, story):
        """Crea la tabla de vulnerabilidades"""
        if not self.analysis_results['vulnerabilities']:
            return
        
        story.append(PageBreak())
        story.append(Paragraph("Vulnerabilidades Detectadas", self.styles['CustomHeading']))
        
        intro_text = """
        Esta sección detalla las vulnerabilidades de seguridad específicas encontradas durante el análisis.
        Cada entrada incluye el host afectado, el tipo de vulnerabilidad, el puerto asociado, el nivel de riesgo y una breve descripción
        para facilitar su identificación y priorización.
        """
        story.append(Paragraph(intro_text, self.styles['CustomBody']))
        
        # Datos de la tabla
        table_data = [['Host', 'Tipo', 'Puerto', 'Riesgo', 'Descripción']]
        
        for vuln in self.analysis_results['vulnerabilities']:
            # Color según riesgo
            risk = vuln['risk']
            
            table_data.append([
                vuln['host'],
                vuln['type'][:20],
                str(vuln['port']),
                risk,
                vuln['description'][:50]
            ])
        
        # Crear tabla
        vulns_table = Table(table_data, colWidths=[1.2*inch, 1.3*inch, 0.6*inch, 0.7*inch, 2.8*inch])
        vulns_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc3545')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        
        story.append(vulns_table)
        story.append(Spacer(1, 0.3*inch))
    
    def _create_recommendations(self, story):
        """Crea la sección de recomendaciones"""
        story.append(PageBreak())
        story.append(Paragraph("Recomendaciones Generales", self.styles['CustomHeading']))
        
        intro_text = """
        Basado en los hallazgos de esta auditoría, se proponen las siguientes mejores prácticas de seguridad.
        La implementación de estas medidas ayudará a mitigar los riesgos identificados y a fortalecer la postura
        de seguridad general de la red.
        """
        story.append(Paragraph(intro_text, self.styles['CustomBody']))
        
        recommendations = [
            "Cerrar todos los puertos innecesarios y aplicar el principio de mínimo privilegio",
            "Actualizar todos los servicios a las versiones más recientes con parches de seguridad",
            "Implementar cifrado en todos los servicios que transmiten información sensible",
            "Configurar firewalls y segmentación de red adecuada",
            "Implementar sistemas de detección y prevención de intrusiones (IDS/IPS)",
            "Realizar auditorías de seguridad periódicas",
            "Mantener un inventario actualizado de todos los activos de red"
        ]
        
        for rec in recommendations:
            p = Paragraph(f"• {rec}", self.styles['CustomBody'])
            story.append(p)
        
        story.append(Spacer(1, 0.2*inch))
    
    def generate_pdf(self) -> str:
        """
        Genera el reporte PDF completo
        
        Returns:
            Ruta del archivo PDF generado
        """
        logger.info("Generando reporte PDF...")
        
        # Nombre del archivo
        pdf_filename = f"{REPORT_FILENAME_PREFIX}_{self.timestamp}.pdf"
        pdf_path = os.path.join(self.report_dir, pdf_filename)
        
        # Crear documento
        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        # Contenido del documento
        story = []
        
        # Añadir secciones
        self._create_header(story)
        self._create_executive_summary(story)
        self._add_charts(story)
        self._create_hosts_table(story)
        self._create_vulnerabilities_table(story)
        self._create_recommendations(story)
        
        # Generar PDF
        try:
            doc.build(story)
            logger.info(f"✓ Reporte PDF generado: {pdf_path}")
            return pdf_path
        except Exception as e:
            logger.error(f"Error generando PDF: {e}")
            raise


if __name__ == "__main__":
    print("Módulo de generación de PDF cargado correctamente")