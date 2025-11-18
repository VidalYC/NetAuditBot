"""
NetAuditBot - Configuración del Sistema
Autor: NetAuditBot Team
Versión: 1.0
"""

import os
from datetime import datetime

# ==================== CONFIGURACIÓN GENERAL ====================
PROJECT_NAME = "NetAuditBot"
VERSION = "1.0.0"
AUTHOR = "NetAuditBot Team"

# ==================== DIRECTORIOS ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Crear directorios si no existen
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# ==================== CONFIGURACIÓN DE ESCANEO ====================
# Puertos comunes a escanear
COMMON_PORTS = "21-23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443"

# Argumentos de Nmap
NMAP_ARGUMENTS = "-sV -sC -O --osscan-guess"

# Timeout del escaneo (en segundos)
SCAN_TIMEOUT = 300

# ==================== CLASIFICACIÓN DE RIESGOS ====================
# Puertos vulnerables conocidos
VULNERABLE_PORTS = {
    21: {"service": "FTP", "risk": "ALTO", "reason": "Protocolo sin cifrado, credenciales en texto plano"},
    23: {"service": "Telnet", "risk": "ALTO", "reason": "Protocolo sin cifrado, altamente inseguro"},
    25: {"service": "SMTP", "risk": "MEDIO", "reason": "Puede ser usado para relay no autorizado"},
    53: {"service": "DNS", "risk": "MEDIO", "reason": "Posible vector de ataques de amplificación"},
    80: {"service": "HTTP", "risk": "MEDIO", "reason": "Tráfico sin cifrado"},
    110: {"service": "POP3", "risk": "ALTO", "reason": "Credenciales sin cifrado"},
    135: {"service": "RPC", "risk": "ALTO", "reason": "Vulnerable a ataques remotos"},
    139: {"service": "NetBIOS", "risk": "ALTO", "reason": "Expone información del sistema"},
    143: {"service": "IMAP", "risk": "MEDIO", "reason": "Credenciales potencialmente sin cifrado"},
    445: {"service": "SMB", "risk": "ALTO", "reason": "Vulnerable a EternalBlue y otros exploits"},
    1433: {"service": "MS SQL", "risk": "ALTO", "reason": "Base de datos expuesta"},
    3306: {"service": "MySQL", "risk": "ALTO", "reason": "Base de datos expuesta"},
    3389: {"service": "RDP", "risk": "ALTO", "reason": "Acceso remoto expuesto, objetivo de fuerza bruta"},
    5432: {"service": "PostgreSQL", "risk": "ALTO", "reason": "Base de datos expuesta"},
    5900: {"service": "VNC", "risk": "ALTO", "reason": "Acceso remoto sin cifrado adecuado"},
    8080: {"service": "HTTP-Proxy", "risk": "MEDIO", "reason": "Servidor web alternativo sin cifrado"},
}

# Servicios que deberían estar cifrados
UNENCRYPTED_SERVICES = ["ftp", "telnet", "http", "smtp", "pop3", "imap"]

# Versiones vulnerables conocidas (ejemplos)
VULNERABLE_VERSIONS = {
    "openssh": ["7.4", "7.3", "6.6"],
    "apache": ["2.2", "2.4.49"],
    "mysql": ["5.5", "5.6"],
    "microsoft-iis": ["6.0", "7.0"],
}

# ==================== UMBRALES DE ALERTA ====================
# Número máximo de puertos abiertos considerado seguro
MAX_SAFE_OPEN_PORTS = 5

# Porcentaje de hosts vulnerables que activa alerta crítica
CRITICAL_VULNERABLE_PERCENTAGE = 50

# ==================== CONFIGURACIÓN DE REPORTES ====================
REPORT_TITLE = "Reporte de Auditoría de Red"
REPORT_FILENAME_PREFIX = "audit_report"

# Colores para clasificación de riesgos (HTML)
RISK_COLORS = {
    "ALTO": "#dc3545",
    "MEDIO": "#ffc107",
    "BAJO": "#28a745",
    "INFO": "#17a2b8"
}

# ==================== CONFIGURACIÓN DE LOGS ====================
LOG_FILENAME = f"netauditbot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# ==================== RECOMENDACIONES DE SEGURIDAD ====================
SECURITY_RECOMMENDATIONS = {
    "FTP": "Migrar a SFTP o FTPS para cifrar las comunicaciones",
    "Telnet": "Reemplazar por SSH para conexiones seguras",
    "HTTP": "Implementar HTTPS con certificados SSL/TLS válidos",
    "SMB": "Actualizar a la última versión y aplicar parches de seguridad",
    "RDP": "Implementar autenticación multifactor y restringir acceso por IP",
    "MySQL": "Cambiar puerto por defecto y restringir acceso remoto",
    "PostgreSQL": "Configurar reglas de firewall y autenticación robusta",
    "MS SQL": "Habilitar cifrado y usar autenticación Windows",
    "VNC": "Usar túnel SSH o reemplazar por alternativas más seguras",
    "DNS": "Configurar DNSSEC y restringir recursión",
}

# ==================== CONFIGURACIÓN DE GRÁFICOS ====================
CHART_STYLE = "default"  # Cambio de 'seaborn' a 'default' por compatibilidad
CHART_DPI = 100
CHART_FIGSIZE = (10, 6)

# ==================== MENSAJES DEL SISTEMA ====================
MESSAGES = {
    "scan_start": "🔍 Iniciando escaneo de red...",
    "scan_complete": "✅ Escaneo completado exitosamente",
    "scan_error": "❌ Error durante el escaneo",
    "report_generated": "📄 Reporte generado exitosamente",
    "no_hosts_found": "⚠️  No se encontraron hosts activos en la red",
}