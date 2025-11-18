# 🛡️ NetAuditBot

**Herramienta de Auditoría de Red Automatizada**

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

---

## 📋 Tabla de Contenidos

- [¿Qué es una Auditoría de Red?](#-qué-es-una-auditoría-de-red)
- [Características](#-características)
- [Arquitectura del Proyecto](#-arquitectura-del-proyecto)
- [Requisitos del Sistema](#-requisitos-del-sistema)
- [Instalación](#-instalación)
- [Manual de Uso Completo](#-manual-de-uso-completo)
- [Interpretación de Resultados](#-interpretación-de-resultados)
- [Ejemplos de Uso](#-ejemplos-de-uso)
- [Solución de Problemas](#-solución-de-problemas)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)

---

## 🔍 ¿Qué es una Auditoría de Red?

Una **auditoría de red** es el proceso sistemático de analizar la infraestructura de red de una organización para:

### Objetivos Principales:

1. **Descubrir Activos**: Identificar todos los dispositivos conectados a la red
2. **Evaluar Seguridad**: Detectar vulnerabilidades y configuraciones inseguras
3. **Cumplimiento**: Verificar que se cumplan políticas de seguridad
4. **Documentación**: Mantener un inventario actualizado de la red
5. **Prevención**: Identificar riesgos antes de que sean explotados

### ¿Por qué es importante?

- 🔒 **Protección de Datos**: Evita brechas de seguridad y robo de información
- 📊 **Visibilidad**: Conocer exactamente qué hay en tu red
- ⚖️ **Cumplimiento Normativo**: Cumplir con regulaciones como GDPR, PCI-DSS
- 💰 **Ahorro de Costos**: Prevenir ataques es más barato que remediar
- 🎯 **Optimización**: Identificar recursos mal configurados o subutilizados

### Tipos de Auditorías que realiza NetAuditBot:

| Tipo | Descripción | Riesgo Detectado |
|------|-------------|------------------|
| **Descubrimiento de Hosts** | Identifica dispositivos activos | Activos no autorizados |
| **Escaneo de Puertos** | Detecta servicios expuestos | Superficie de ataque |
| **Detección de Servicios** | Identifica software y versiones | Software vulnerable |
| **Análisis de Vulnerabilidades** | Evalúa configuraciones inseguras | Riesgos críticos |

---

## ✨ Características

### 🔍 Capacidades de Escaneo
- ✅ Descubrimiento automático de hosts activos
- ✅ Escaneo de puertos comunes y personalizados
- ✅ Detección de servicios y versiones
- ✅ Identificación de sistemas operativos
- ✅ Análisis de protocolos sin cifrado

### 🔐 Análisis de Seguridad
- ✅ Detección de puertos vulnerables conocidos
- ✅ Identificación de servicios sin cifrado
- ✅ Análisis de versiones de software vulnerables
- ✅ Evaluación de exceso de puertos abiertos
- ✅ Clasificación de riesgos (ALTO, MEDIO, BAJO)

### 📊 Reportes Profesionales
- ✅ Reportes HTML interactivos con gráficos
- ✅ Generación de PDF (opcional)
- ✅ Gráficos de distribución de riesgos
- ✅ Análisis visual de puertos y servicios
- ✅ Recomendaciones de seguridad detalladas

### 🎯 Facilidad de Uso
- ✅ Interfaz de línea de comandos intuitiva
- ✅ Sistema de diagnóstico incluido
- ✅ Logging detallado para auditoría
- ✅ Configuración centralizada

---

## 🛠️ Tecnologías y Herramientas Utilizadas

### Lenguajes de Programación

| Tecnología | Versión | Propósito | Documentación |
|------------|---------|-----------|---------------|
| **Python** | 3.9+ | Lenguaje principal del proyecto | [python.org](https://www.python.org/) |
| **HTML5** | - | Estructura de reportes web | [MDN HTML](https://developer.mozilla.org/en-US/docs/Web/HTML) |
| **CSS3** | - | Estilos y diseño de reportes | [MDN CSS](https://developer.mozilla.org/en-US/docs/Web/CSS) |
| **JavaScript** | ES6 | Interactividad en reportes (mínima) | [MDN JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript) |

### Librerías Python Core

#### 1. **python-nmap** (v0.7.1+)
```python
import nmap
nm = nmap.PortScanner()
```
- **Propósito**: Wrapper de Python para Nmap
- **Uso en el proyecto**: 
  - Descubrimiento de hosts activos
  - Escaneo de puertos
  - Detección de servicios y versiones
  - Identificación de sistemas operativos
- **Alternativas consideradas**: python-libnmap, nmap3
- **Por qué se eligió**: Más estable, mejor documentada, amplio soporte comunitario
- **Licencia**: GPL v3

#### 2. **Jinja2** (v3.1.2+)
```python
from jinja2 import Template
template = Template(html_content)
```
- **Propósito**: Motor de templates para Python
- **Uso en el proyecto**:
  - Generación dinámica de reportes HTML
  - Renderizado de tablas y gráficos
  - Personalización de reportes
- **Características utilizadas**:
  - Variables y expresiones: `{{ variable }}`
  - Estructuras de control: `{% for %} {% if %}`
  - Filtros: `{{ data|length }}`
  - Herencia de templates
- **Licencia**: BSD-3-Clause

#### 3. **Matplotlib** (v3.5.0+)
```python
import matplotlib.pyplot as plt
plt.bar(x, y)
```
- **Propósito**: Librería de visualización de datos
- **Uso en el proyecto**:
  - Gráficos de barras para distribución de riesgos
  - Gráficos horizontales para tipos de vulnerabilidades
  - Gráficos de puertos abiertos por host
  - Charts de servicios más comunes
- **Tipos de gráficos generados**:
  - Bar charts (`plt.bar()`)
  - Horizontal bar charts (`plt.barh()`)
  - Line plots para umbrales
- **Backend utilizado**: Agg (sin GUI)
- **Licencia**: PSF-based

#### 4. **Pandas** (v1.4.0+)
```python
import pandas as pd
df = pd.DataFrame(data)
```
- **Propósito**: Análisis y manipulación de datos
- **Uso en el proyecto**:
  - Organización de resultados de escaneo
  - Procesamiento de vulnerabilidades
  - Generación de estadísticas
  - Estructuración de datos para reportes
- **Estructuras utilizadas**:
  - DataFrames para tablas de hosts
  - Series para métricas
- **Licencia**: BSD-3-Clause

#### 5. **ReportLab** (v3.6.0+) - Opcional
```python
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate
```
- **Propósito**: Generación de documentos PDF
- **Uso en el proyecto**:
  - Creación de reportes PDF profesionales
  - Diseño de páginas con tablas y gráficos
  - Formato corporativo de documentos
- **Componentes utilizados**:
  - `SimpleDocTemplate`: Estructura del PDF
  - `Table` y `TableStyle`: Tablas formateadas
  - `Paragraph`: Texto con estilos
  - `Image`: Inclusión de gráficos
- **Licencia**: BSD-like

### Herramientas Externas

#### **Nmap** (Network Mapper) - v7.80+
```bash
nmap -sV -sC -O 192.168.1.0/24
```
- **Propósito**: Escáner de red y auditoría de seguridad
- **Características utilizadas**:
  - `-sn`: Ping scan (descubrimiento de hosts)
  - `-sV`: Detección de versiones de servicios
  - `-sC`: Scripts de enumeración
  - `-O`: Detección de sistema operativo
  - `--osscan-guess`: Estimación de OS
- **Por qué Nmap**:
  - ✅ Estándar de la industria para auditoría de red
  - ✅ Base de datos NSE (Nmap Scripting Engine)
  - ✅ Detección precisa de servicios
  - ✅ Comunidad activa y actualizaciones constantes
- **Sitio oficial**: https://nmap.org
- **Licencia**: Nmap Public Source License

### Librerías Python Estándar (Built-in)

| Librería | Uso en el Proyecto |
|----------|-------------------|
| `os` | Gestión de rutas y directorios |
| `sys` | Argumentos de línea de comandos |
| `logging` | Sistema de logs y auditoría |
| `datetime` | Timestamps y fechas en reportes |
| `argparse` | Parseo de argumentos CLI |
| `subprocess` | Ejecución de comandos del sistema |
| `json` | Manejo de datos estructurados |
| `time` | Medición de tiempos de ejecución |
| `platform` | Detección del sistema operativo |

### Tecnologías Web para Reportes

#### **HTML5**
```html
<!DOCTYPE html>
<html lang="es">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
</html>
```
- **Elementos utilizados**:
  - Estructura semántica: `<header>`, `<section>`, `<footer>`
  - Tablas: `<table>`, `<thead>`, `<tbody>`
  - Listas: `<ul>`, `<ol>`, `<li>`
  - Imágenes: `<img>` para gráficos
- **Características modernas**:
  - Responsive design con viewport
  - Metadatos para SEO

#### **CSS3**
```css
body {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}
```
- **Técnicas utilizadas**:
  - **Flexbox**: Layout flexible para cards
  - **Grid Layout**: Diseño de dashboard
  - **Gradientes**: Backgrounds atractivos
  - **Transiciones**: Efectos hover suaves
  - **Box Shadow**: Profundidad visual
  - **Border Radius**: Esquinas redondeadas
- **Filosofía de diseño**:
  - Mobile-first approach
  - Paleta de colores profesional
  - Tipografía legible

### Arquitectura y Patrones

#### **Patrón de Diseño: Modular**
```
netauditbot.py (Orchestrator)
    ├── scanner.py (Single Responsibility)
    ├── security_analyzer.py (Single Responsibility)
    └── report_generator.py (Single Responsibility)
```
- **Principios aplicados**:
  - **SRP**: Cada módulo tiene una responsabilidad única
  - **DRY**: No repetir código con `config.py`
  - **KISS**: Mantener simple y legible

#### **Patrón de Diseño: Pipeline**
```python
Entrada → Escaneo → Análisis → Reporte → Salida
```
- Flujo secuencial de datos
- Cada fase procesa resultados de la anterior
- Manejo de errores en cada etapa

### Control de Versiones

#### **Git**
```bash
git init
git add .
git commit -m "Initial commit"
```
- **Archivo `.gitignore`**: Excluye archivos temporales
- **Branches recomendadas**:
  - `main`: Versión estable
  - `develop`: Desarrollo activo
  - `feature/*`: Nuevas características

### Entornos Virtuales

#### **venv** (Python Virtual Environment)
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```
- **Propósito**: Aislar dependencias del proyecto
- **Beneficios**:
  - Evita conflictos de versiones
  - Reproduce ambiente exacto
  - Facilita deployment

### Gestión de Dependencias

#### **pip** + **requirements.txt**
```txt
python-nmap>=0.7.1
jinja2>=3.1.2
matplotlib>=3.5.0
pandas>=1.4.0
reportlab>=3.6.0
```
- **Especificación de versiones**:
  - `>=`: Versión mínima compatible
  - `==`: Versión exacta (para producción)
- **Instalación**: `pip install -r requirements.txt`

### Herramientas de Desarrollo

| Herramienta | Propósito | Opcional |
|-------------|-----------|----------|
| **VS Code** | Editor de código recomendado | ✅ |
| **PyCharm** | IDE completo para Python | ✅ |
| **Git** | Control de versiones | ❌ |
| **VirtualBox** | Crear entorno de pruebas | ✅ |
| **Wireshark** | Análisis de tráfico (debugging) | ✅ |

### Sistema de Logs

#### **Python logging**
```python
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```
- **Niveles utilizados**:
  - `DEBUG`: Información detallada para desarrollo
  - `INFO`: Eventos generales del flujo
  - `WARNING`: Situaciones inesperadas no críticas
  - `ERROR`: Errores que afectan funcionalidad
  - `CRITICAL`: Errores graves que detienen ejecución
- **Destinos**:
  - Consola (stdout)
  - Archivo en `logs/netauditbot_*.log`

### Formato de Datos

#### **JSON** (JavaScript Object Notation)
```json
{
  "host": "192.168.1.100",
  "ports": [21, 22, 80],
  "vulnerabilities": [...]
}
```
- **Uso**: Estructuración interna de datos
- **Ventajas**: Fácil de leer y parsear

### Compatibilidad

#### **Sistemas Operativos Soportados**
| OS | Versión | Estado | Notas |
|----|---------|--------|-------|
| **Windows** | 10, 11 | ✅ Completo | Requiere Nmap instalado |
| **Linux** | Ubuntu 20.04+, Debian 10+ | ✅ Completo | Requiere sudo para OS detection |
| **macOS** | 11.0+ (Big Sur) | ✅ Completo | Instalar Nmap con Homebrew |

#### **Versiones de Python Soportadas**
```
✅ Python 3.9
✅ Python 3.10
✅ Python 3.11
✅ Python 3.12
❌ Python 3.8 (no probado)
❌ Python 2.x (incompatible)
```

### Stack Tecnológico Completo

```
┌─────────────────────────────────────────┐
│         Capa de Presentación            │
│  HTML5 + CSS3 + Matplotlib Charts       │
├─────────────────────────────────────────┤
│         Capa de Aplicación              │
│  Python 3.9+ (netauditbot.py)          │
├─────────────────────────────────────────┤
│         Capa de Lógica                  │
│  scanner.py + security_analyzer.py      │
│  report_generator.py                    │
├─────────────────────────────────────────┤
│         Capa de Datos                   │
│  Pandas DataFrames + JSON               │
├─────────────────────────────────────────┤
│         Capa de Red                     │
│  Nmap (python-nmap wrapper)            │
├─────────────────────────────────────────┤
│         Sistema Operativo               │
│  Windows / Linux / macOS                │
└─────────────────────────────────────────┘
```

### Métricas del Proyecto

| Métrica | Valor | Descripción |
|---------|-------|-------------|
| **Líneas de código** | ~2,500 | Python, HTML, CSS combinados |
| **Módulos Python** | 7 | Archivos .py principales |
| **Dependencias externas** | 5 | Librerías pip |
| **Tamaño del proyecto** | ~100 KB | Sin incluir venv/ y reports/ |
| **Tiempo de escaneo** | 1-30 min | Depende del tamaño de red |
| **Formato de salida** | HTML/PDF | Reportes generados |

### Justificación de Elecciones Tecnológicas

#### ¿Por qué Python?
- ✅ Sintaxis clara y legible
- ✅ Amplio ecosistema de librerías
- ✅ Excelente para scripting y automatización
- ✅ Comunidad activa en ciberseguridad
- ✅ Multiplataforma sin modificaciones

#### ¿Por qué Nmap?
- ✅ Estándar de facto en auditoría de redes
- ✅ Base de datos de servicios más completa
- ✅ Scripts NSE para detección avanzada
- ✅ Activamente mantenido (20+ años)
- ✅ Usado por profesionales de seguridad

#### ¿Por qué Matplotlib sobre otras librerías?
- ✅ Gráficos de alta calidad para reportes
- ✅ Exportación sencilla a PNG
- ✅ Ampliamente documentado
- ❌ Alternativas consideradas:
  - Plotly: Más pesado, requiere JavaScript
  - Seaborn: Dependencia extra innecesaria
  - Chart.js: Requiere renderizado en navegador

#### ¿Por qué HTML+CSS sobre frameworks?
- ✅ Sin dependencias adicionales
- ✅ Compatible con cualquier navegador
- ✅ Fácil de personalizar
- ✅ No requiere servidor web
- ❌ Frameworks descartados:
  - Bootstrap: Overhead innecesario
  - React: Complejidad no justificada
  - Vue: Similar a React

---

## 🏗️ Arquitectura del Proyecto

### Estructura de Archivos

```
NetAuditBot/
│
├── 📄 netauditbot.py          # Script principal - Orquestador
├── 📄 config.py               # Configuración centralizada
├── 📄 scanner.py              # Módulo de escaneo de red
├── 📄 security_analyzer.py    # Módulo de análisis de seguridad
├── 📄 report_generator.py     # Generador de reportes HTML
├── 📄 pdf_generator.py        # Generador de reportes PDF
├── 📄 diagnostic.py           # Sistema de diagnóstico
├── 📄 requirements.txt        # Dependencias Python
├── 📄 .gitignore             # Archivos ignorados por Git
│
├── 📁 reports/               # Reportes generados (auto-creado)
│   └── report_YYYYMMDD_HHMMSS/
│       ├── audit_report_*.html
│       ├── audit_report_*.pdf
│       └── *.png             # Gráficos generados
│
├── 📁 logs/                  # Archivos de log (auto-creado)
│   └── netauditbot_*.log
│
└── 📁 templates/             # Plantillas (auto-creado)
```

### 🧩 Componentes Detallados

#### 1. **netauditbot.py** - Orquestador Principal
```
Responsabilidades:
├── Parseo de argumentos de línea de comandos
├── Validación de requisitos del sistema
├── Coordinación de las 3 fases:
│   ├── Fase 1: Escaneo de red
│   ├── Fase 2: Análisis de seguridad
│   └── Fase 3: Generación de reportes
└── Gestión de errores y logging
```

**Flujo de Ejecución:**
```
Inicio → Verificar requisitos → Escaneo → Análisis → Reporte → Fin
```

#### 2. **config.py** - Centro de Configuración
```python
Contiene:
├── Configuraciones generales (nombre, versión, autor)
├── Rutas de directorios
├── Parámetros de escaneo
│   ├── Puertos comunes a escanear
│   ├── Argumentos de Nmap
│   └── Timeouts
├── Base de datos de vulnerabilidades
│   ├── Puertos vulnerables conocidos
│   ├── Servicios sin cifrado
│   └── Versiones vulnerables
├── Umbrales de seguridad
├── Recomendaciones de seguridad
└── Configuración de reportes
```

**Puertos Monitoreados por Defecto:**
- **21** (FTP), **23** (Telnet), **25** (SMTP)
- **53** (DNS), **80** (HTTP), **110** (POP3)
- **135** (RPC), **139** (NetBIOS), **143** (IMAP)
- **443** (HTTPS), **445** (SMB), **3389** (RDP)
- **3306** (MySQL), **5432** (PostgreSQL), **1433** (MS SQL)
- Y más...

#### 3. **scanner.py** - Motor de Escaneo
```
Clase: NetworkScanner
│
├── discover_hosts()
│   └── Realiza ping sweep para encontrar hosts activos
│
├── scan_host(ip)
│   ├── Escanea puertos del host
│   ├── Detecta servicios y versiones
│   ├── Identifica sistema operativo
│   └── Recopila información de cada puerto
│
├── scan_network()
│   └── Coordina el escaneo completo de la red
│
└── get_summary()
    └── Genera estadísticas del escaneo
```

**Tecnología:** Utiliza `python-nmap` como wrapper de Nmap

**Información Recopilada:**
- IP y hostname de cada host
- Estado del host (up/down)
- Sistema operativo detectado
- Lista de puertos abiertos con:
  - Número de puerto
  - Servicio identificado
  - Versión del software
  - Información adicional

#### 4. **security_analyzer.py** - Analizador de Seguridad
```
Clase: SecurityAnalyzer
│
├── analyze_vulnerable_ports()
│   └── Identifica puertos conocidos como inseguros
│
├── analyze_unencrypted_services()
│   └── Detecta servicios que transmiten sin cifrado
│
├── analyze_vulnerable_versions()
│   └── Busca versiones de software con CVEs conocidos
│
├── analyze_excessive_ports()
│   └── Identifica hosts con demasiados puertos abiertos
│
├── analyze_all()
│   └── Ejecuta todos los análisis y consolida resultados
│
└── get_host_risk_score(ip)
    └── Calcula score de riesgo para un host específico
```

**Clasificación de Riesgos:**

| Nivel | Criterio | Acción Requerida |
|-------|----------|------------------|
| 🔴 **ALTO** | Puertos críticos expuestos, servicios vulnerables | Inmediata |
| 🟡 **MEDIO** | Servicios sin cifrado, configuraciones débiles | Planificada |
| 🟢 **BAJO** | Buenas prácticas no seguidas | Revisión |

#### 5. **report_generator.py** - Generador de Reportes
```
Clase: ReportGenerator
│
├── generate_charts()
│   ├── Distribución de riesgos (gráfico de barras)
│   ├── Tipos de vulnerabilidades (gráfico horizontal)
│   ├── Puertos abiertos por host (gráfico de barras)
│   └── Top servicios detectados (gráfico horizontal)
│
├── generate_html_report()
│   ├── Renderiza template HTML con Jinja2
│   ├── Incluye gráficos generados
│   ├── Tabla de hosts detectados
│   ├── Tabla de vulnerabilidades
│   └── Recomendaciones de seguridad
│
└── generate()
    └── Orquesta generación completa del reporte
```

**Tecnologías Utilizadas:**
- **Matplotlib**: Generación de gráficos
- **Jinja2**: Sistema de templates para HTML
- **CSS3**: Diseño responsivo y moderno

#### 6. **pdf_generator.py** - Generador de PDF (Opcional)
```
Clase: PDFReportGenerator
│
├── _create_header()
├── _create_executive_summary()
├── _add_charts()
├── _create_hosts_table()
├── _create_vulnerabilities_table()
├── _create_recommendations()
│
└── generate_pdf()
    └── Compila todo en documento PDF profesional
```

**Tecnología:** ReportLab para generación de PDF

#### 7. **diagnostic.py** - Sistema de Diagnóstico
```
Funciones:
├── check_python()         # Verifica versión de Python
├── check_nmap()          # Verifica instalación de Nmap
├── check_python_modules() # Verifica dependencias Python
├── check_files()         # Verifica archivos del proyecto
├── check_permissions()   # Verifica permisos de escritura
└── run_diagnostics()     # Ejecuta todos los checks
```

---

## 💻 Requisitos del Sistema

### Requisitos Mínimos

| Componente | Requisito | Notas |
|------------|-----------|-------|
| **Sistema Operativo** | Windows 10/11, Linux, macOS | Cualquier SO compatible con Python |
| **Python** | 3.9 o superior | Versión 3.11+ recomendada |
| **RAM** | 2 GB | 4 GB recomendado para redes grandes |
| **Espacio en Disco** | 100 MB | Más espacio para reportes |
| **Nmap** | 7.80 o superior | Herramienta externa requerida |
| **Conexión de Red** | Acceso a red objetivo | Permisos de red necesarios |

### Dependencias Python

```txt
python-nmap >= 0.7.1    # Wrapper de Nmap
jinja2 >= 3.1.2         # Motor de templates
matplotlib >= 3.5.0     # Generación de gráficos
pandas >= 1.4.0         # Análisis de datos
reportlab >= 3.6.0      # Generación de PDF (opcional)
```

---

## 🚀 Instalación

### Opción 1: Instalación Rápida (Recomendada)

#### En Windows:

```powershell
# 1. Instalar Python 3.11 desde python.org

# 2. Instalar Nmap
# Descargar desde: https://nmap.org/download.html
# Ejecutar instalador y seguir pasos

# 3. Clonar repositorio
git clone https://github.com/tu-usuario/NetAuditBot.git
cd NetAuditBot

# 4. Crear entorno virtual
python -m venv venv
venv\Scripts\activate

# 5. Instalar dependencias
pip install -r requirements.txt

# 6. Verificar instalación
python diagnostic.py
```

#### En Linux (Ubuntu/Debian):

```bash
# 1. Actualizar sistema
sudo apt update && sudo apt upgrade -y

# 2. Instalar Python y Nmap
sudo apt install python3 python3-pip python3-venv nmap -y

# 3. Clonar repositorio
git clone https://github.com/tu-usuario/NetAuditBot.git
cd NetAuditBot

# 4. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 5. Instalar dependencias
pip install -r requirements.txt

# 6. Verificar instalación
python diagnostic.py
```

#### En macOS:

```bash
# 1. Instalar Homebrew (si no está instalado)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Instalar Python y Nmap
brew install python@3.11 nmap

# 3. Clonar repositorio
git clone https://github.com/tu-usuario/NetAuditBot.git
cd NetAuditBot

# 4. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 5. Instalar dependencias
pip install -r requirements.txt

# 6. Verificar instalación
python diagnostic.py
```

### Opción 2: Instalación Manual

1. **Descargar el proyecto**
   ```bash
   # Descargar como ZIP desde GitHub
   # O clonar: git clone https://github.com/tu-usuario/NetAuditBot.git
   ```

2. **Instalar Nmap manualmente**
   - Windows: https://nmap.org/download.html
   - Linux: `sudo apt install nmap`
   - macOS: `brew install nmap`

3. **Instalar dependencias una por una**
   ```bash
   pip install python-nmap
   pip install jinja2
   pip install matplotlib
   pip install pandas
   pip install reportlab  # Opcional, para PDF
   ```

### Verificación de Instalación

```bash
# Ejecutar diagnóstico completo
python diagnostic.py
```

**Salida esperada:**
```
╔═══════════════════════════════════════════════╗
║   NetAuditBot - Diagnóstico del Sistema      ║
╚═══════════════════════════════════════════════╝

============================================================
  VERIFICANDO PYTHON
============================================================
Versión: Python 3.11.0
Ejecutable: /usr/bin/python3
Plataforma: Linux 5.15.0
✅ Versión de Python correcta

============================================================
  VERIFICANDO NMAP
============================================================
✅ Nmap version 7.92

============================================================
  VERIFICANDO MÓDULOS DE PYTHON
============================================================
✅ python-nmap: 0.7.1
✅ Jinja2: 3.1.2
✅ Matplotlib: 3.7.1
✅ Pandas: 2.0.0
✅ ReportLab: 4.0.4

============================================================
  VERIFICANDO ARCHIVOS DEL PROYECTO
============================================================
✅ config.py
✅ scanner.py
✅ security_analyzer.py
✅ report_generator.py
✅ netauditbot.py

============================================================
  VERIFICANDO PERMISOS
============================================================
✅ ./ - Permisos de escritura OK
✅ reports/ - Permisos de escritura OK
✅ logs/ - Permisos de escritura OK

============================================================
  RESUMEN DE DIAGNÓSTICO
============================================================
PYTHON         : ✅ OK
NMAP           : ✅ OK
MODULES        : ✅ OK
FILES          : ✅ OK
PERMISSIONS    : ✅ OK

Resultado: 5/5 verificaciones pasadas

🎉 ¡EXCELENTE! Todos los requisitos están satisfechos.
   Puedes ejecutar NetAuditBot sin problemas.
```

---

## 📖 Manual de Uso Completo

### 🎯 Sintaxis Básica

```bash
python netauditbot.py <red_objetivo> [opciones]
```

### 📝 Parámetros

| Parámetro | Tipo | Descripción | Requerido |
|-----------|------|-------------|-----------|
| `<red_objetivo>` | String | Red o rango de IPs a auditar | ✅ Sí |
| `-v, --verbose` | Flag | Modo detallado con más información | ❌ No |
| `--pdf` | Flag | Genera reporte en PDF además de HTML | ❌ No |
| `--version` | Flag | Muestra la versión del programa | ❌ No |

### 🌐 Formatos de Red Soportados

#### 1. **Notación CIDR** (Recomendado)
```bash
# Escanear red completa (256 hosts)
python netauditbot.py 192.168.1.0/24

# Escanear subred pequeña (16 hosts)
python netauditbot.py 10.0.0.0/28

# Escanear red empresarial (65,536 hosts)
python netauditbot.py 172.16.0.0/16
```

#### 2. **Rango de IPs**
```bash
# Rango específico
python netauditbot.py 192.168.1.100-120

# Rango amplio
python netauditbot.py 10.0.0.1-255
```

#### 3. **IP Individual**
```bash
# Un solo host
python netauditbot.py 192.168.1.100

# Servidor específico
python netauditbot.py 10.0.0.50
```

#### 4. **Lista de IPs**
```bash
# Múltiples IPs separadas por comas
python netauditbot.py 192.168.1.1,192.168.1.10,192.168.1.20
```

### 🔍 Ejemplos Prácticos

#### Ejemplo 1: Auditoría Básica de Red Local
```bash
# Escaneo simple de red doméstica
python netauditbot.py 192.168.1.0/24
```

**Qué hace:**
- Descubre todos los dispositivos conectados a tu router
- Escanea puertos comunes (21, 22, 23, 80, 443, etc.)
- Genera reporte HTML en `reports/`

#### Ejemplo 2: Auditoría Detallada con Modo Verbose
```bash
# Escaneo con información detallada en consola
python netauditbot.py 192.168.1.0/24 -v
```

**Qué hace:**
- Todo lo del ejemplo 1, PLUS:
- Muestra progreso detallado en tiempo real
- Lista las top 5 vulnerabilidades en consola
- Más información de logging

#### Ejemplo 3: Auditoría Completa con PDF
```bash
# Escaneo con reporte HTML + PDF
python netauditbot.py 192.168.1.0/24 --pdf
```

**Qué hace:**
- Genera reporte HTML (siempre)
- Genera reporte PDF adicional
- Perfecto para presentaciones ejecutivas

#### Ejemplo 4: Auditoría de Servidores Específicos
```bash
# Escanear solo servidores críticos
python netauditbot.py 192.168.1.100-105 -v --pdf
```

**Uso típico:** Servidores en DMZ o zona de producción

#### Ejemplo 5: Auditoría con Permisos de Administrador
```bash
# Linux/macOS - Escaneo con sudo para detección de OS
sudo python netauditbot.py 192.168.1.0/24 -v

# Windows - Ejecutar PowerShell/CMD como Administrador
python netauditbot.py 192.168.1.0/24 -v
```

**Beneficios de sudo/admin:**
- Detección más precisa de sistemas operativos
- Acceso a técnicas de escaneo avanzadas de Nmap
- Resultados más completos

### 📊 Proceso Paso a Paso

#### **Fase 1: Escaneo de Red** 🔍
```
🔍 FASE 1: ESCANEO DE RED
------------------------------------------------------------
[1/3] Procesando host: 192.168.1.1
  Puerto 80 abierto: http
  Puerto 443 abierto: https

[2/3] Procesando host: 192.168.1.10
  Puerto 22 abierto: ssh
  Puerto 80 abierto: http

[3/3] Procesando host: 192.168.1.100
  Puerto 21 abierto: ftp
  Puerto 80 abierto: http
  Puerto 3306 abierto: mysql

✅ Escaneo completado:
   • Hosts encontrados: 3
   • Puertos abiertos: 7
   • Servicios únicos: 5
```

**Tiempo estimado:**
- Red pequeña (1-10 hosts): 1-3 minutos
- Red mediana (11-50 hosts): 5-10 minutos
- Red grande (50+ hosts): 15-30 minutos

#### **Fase 2: Análisis de Seguridad** 🔐
```
🔐 FASE 2: ANÁLISIS DE SEGURIDAD
------------------------------------------------------------
Analizando puertos vulnerables...
Analizando servicios sin cifrado...
Analizando versiones de software...
Analizando configuraciones...

✅ Análisis completado:
   • Total vulnerabilidades: 8
   • Riesgo ALTO: 3
   • Riesgo MEDIO: 4
   • Riesgo BAJO: 1

⚠️  ALERTA: Se detectaron 3 vulnerabilidades de ALTO riesgo

📋 Top vulnerabilidades encontradas:
   1. [ALTO] 192.168.1.100 - Puerto FTP expuesto sin cifrado
   2. [ALTO] 192.168.1.100 - Base de datos MySQL expuesta
   3. [ALTO] 192.168.1.1 - Servicio Telnet habilitado
   4. [MEDIO] 192.168.1.10 - Servidor HTTP sin SSL
   5. [MEDIO] 192.168.1.1 - DNS expuesto públicamente
```

#### **Fase 3: Generación de Reporte** 📄
```
📄 FASE 3: GENERACIÓN DE REPORTE
------------------------------------------------------------
Generando gráficos...
  ✓ Gráfico de riesgos generado
  ✓ Gráfico de tipos generado
  ✓ Gráfico de puertos generado
  ✓ Gráfico de servicios generado

Generando reporte HTML...
✓ Reporte HTML generado: reports/report_20240115_143022/audit_report_20240115_143022.html

Generando reporte PDF...
✓ Reporte PDF generado: reports/report_20240115_143022/audit_report_20240115_143022.pdf

✅ Reporte generado exitosamente:
   📁 reports/report_20240115_143022/audit_report_20240115_143022.html
```

#### **Resumen Final** ✅
```
============================================================
✅ AUDITORÍA COMPLETADA EXITOSAMENTE
============================================================
⏱️  Tiempo total: 287.45 segundos
📊 Hosts analizados: 3
🔍 Vulnerabilidades: 8
📄 Reporte: reports/report_20240115_143022/audit_report_20240115_143022.html
============================================================

💡 Consejo: Abra el reporte HTML en su navegador para ver los resultados completos
```

### 🎨 Visualización del Reporte

El reporte HTML generado incluye:

1. **Header con Resumen Ejecutivo**
   - Total de hosts, puertos, vulnerabilidades
   - Alertas visuales para riesgos críticos

2. **Cards de Estadísticas**
   - Hosts escaneados
   - Puertos abiertos
   - Total vulnerabilidades
   - Riesgo alto

3. **Gráficos Interactivos**
   - Distribución de riesgos (barras)
   - Tipos de vulnerabilidades (horizontal)
   - Puertos abiertos por host
   - Top servicios detectados

4. **Tabla de Hosts Detectados**
   - IP, Hostname, OS
   - Número de puertos abiertos
   - Estado de seguridad

5. **Tabla de Vulnerabilidades**
   - Host afectado
   - Tipo de vulnerabilidad
   - Puerto y servicio
   - Nivel de riesgo
   - Descripción
   - Recomendación específica

6. **Recomendaciones Generales**
   - Lista de mejores prácticas
   - Acciones correctivas sugeridas

---

## 📊 Interpretación de Resultados

### 🎯 Entendiendo los Niveles de Riesgo

#### 🔴 **RIESGO ALTO** - Acción Inmediata Requerida
**Características:**
- Puertos críticos expuestos (FTP, Telnet, RDP)
- Bases de datos accesibles desde red
- Servicios con vulnerabilidades conocidas (CVEs)
- Protocolos sin autenticación

**Ejemplos:**
```
[ALTO] Puerto 21 (FTP) - Credenciales en texto plano
[ALTO] Puerto 3389 (RDP) - Acceso remoto expuesto
[ALTO] Puerto 445 (SMB) - Vulnerable a EternalBlue
[ALTO] MySQL 5.5 - Versión con múltiples CVEs
```

**Acciones Recomendadas:**
1. ⚡ Cerrar puerto inmediatamente o restringir por firewall
2. 🔒 Migrar a alternativa segura (SFTP, SSH, VPN)
3. 🔄 Actualizar a última versión del software
4. 🛡️ Implementar autenticación multifactor

#### 🟡 **RIESGO MEDIO** - Planificar Corrección
**Características:**
- Servicios sin cifrado (HTTP, SMTP, POP3)
- Configuraciones débiles
- Exceso de puertos abiertos
- Servicios innecesarios activos

**Ejemplos:**
```
[MEDIO] Puerto 80 (HTTP) - Tráfico sin cifrado
[MEDIO] Puerto 25 (SMTP) - Email sin TLS
[MEDIO] Host con 12 puertos abiertos (umbral: 5)
[MEDIO] Puerto 53 (DNS) - Posible amplificación
```

**Acciones Recomendadas:**
1. 🔐 Implementar certificados SSL/TLS
2. 📉 Reducir superficie de ataque
3. ⚙️ Revisar configuraciones
4. 📅 Programar mantenimiento

#### 🟢 **RIESGO BAJO** - Revisión Periódica
**Características:**
- Buenas prácticas no seguidas
- Optimizaciones recomendadas
- Documentación necesaria

**Ejemplos:**
```
[BAJO] Puerto 443 (HTTPS) - Certificado por vencer
[BAJO] Falta documentación de servicios
[BAJO] No hay política de contraseñas documentada
```

**Acciones Recomendadas:**
1. 📝 Documentar configuraciones
2. 🔄 Establecer calendario de revisiones
3. 📊 Implementar monitoreo

### 📈 Análisis de Gráficos

#### **Gráfico 1: Distribución de Vulnerabilidades por Riesgo**
```
Este gráfico de barras muestra:
├── Eje Y: Cantidad de vulnerabilidades
├── Eje X: Nivel de riesgo (ALTO, MEDIO, BAJO)
└── Interpretación:
    ├── Barras altas en ALTO = Red muy vulnerable
    ├── Barras altas en MEDIO = Configuración mejorable
    └── Sin barras = Red segura
```

**Ejemplo de Interpretación:**
```
ALTO: ████████ (8)  ← CRÍTICO: Atención inmediata
MEDIO: ████ (4)      ← IMPORTANTE: Planificar corrección
BAJO: ██ (2)         ← MENOR: Buenas prácticas
```

#### **Gráfico 2: Tipos de Vulnerabilidades**
```
Muestra la distribución por categoría:
├── Puerto Vulnerable: Cantidad de puertos inseguros
├── Servicio sin Cifrado: Protocolos en texto plano
├── Versión Vulnerable
