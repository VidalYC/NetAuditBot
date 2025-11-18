#!/usr/bin/env python3
"""
NetAuditBot - Script de Diagnóstico
Verifica que todas las dependencias estén instaladas correctamente
"""

import sys
import subprocess
import platform

def print_header(text):
    """Imprime un encabezado formateado"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def check_python():
    """Verifica la versión de Python"""
    print_header("VERIFICANDO PYTHON")
    
    version = sys.version_info
    print(f"Versión: Python {version.major}.{version.minor}.{version.micro}")
    print(f"Ejecutable: {sys.executable}")
    print(f"Plataforma: {platform.system()} {platform.release()}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print("❌ ADVERTENCIA: Se requiere Python 3.9 o superior")
        return False
    else:
        print("✅ Versión de Python correcta")
        return True

def check_nmap():
    """Verifica que Nmap esté instalado"""
    print_header("VERIFICANDO NMAP")
    
    try:
        result = subprocess.run(
            ['nmap', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"✅ {version_line}")
            return True
        else:
            print("❌ Nmap instalado pero no responde correctamente")
            return False
            
    except FileNotFoundError:
        print("❌ Nmap NO está instalado")
        print("\n   Instalar desde:")
        print("   - Windows: https://nmap.org/download.html")
        print("   - Linux: sudo apt-get install nmap")
        print("   - macOS: brew install nmap")
        return False
    except Exception as e:
        print(f"❌ Error al verificar Nmap: {e}")
        return False

def check_python_module(module_name, display_name=None):
    """Verifica si un módulo de Python está instalado"""
    if display_name is None:
        display_name = module_name
    
    try:
        module = __import__(module_name)
        version = getattr(module, '__version__', 'Versión desconocida')
        print(f"✅ {display_name}: {version}")
        return True
    except ImportError:
        print(f"❌ {display_name}: NO INSTALADO")
        return False

def check_python_modules():
    """Verifica todos los módulos de Python necesarios"""
    print_header("VERIFICANDO MÓDULOS DE PYTHON")
    
    modules = [
        ('nmap', 'python-nmap'),
        ('jinja2', 'Jinja2'),
        ('matplotlib', 'Matplotlib'),
        ('pandas', 'Pandas'),
        ('reportlab', 'ReportLab')
    ]
    
    all_ok = True
    missing_modules = []
    
    for module_name, display_name in modules:
        if not check_python_module(module_name, display_name):
            all_ok = False
            missing_modules.append(module_name if module_name != 'nmap' else 'python-nmap')
    
    if not all_ok:
        print("\n⚠️  Módulos faltantes detectados")
        print("\n   Instalar con:")
        print(f"   pip install {' '.join(missing_modules)}")
        print("\n   O usar requirements.txt:")
        print("   pip install -r requirements.txt")
    
    return all_ok

def check_files():
    """Verifica que los archivos del proyecto existan"""
    print_header("VERIFICANDO ARCHIVOS DEL PROYECTO")
    
    import os
    
    required_files = [
        'config.py',
        'scanner.py',
        'security_analyzer.py',
        'report_generator.py',
        'netauditbot.py'
    ]
    
    all_ok = True
    
    for filename in required_files:
        if os.path.exists(filename):
            print(f"✅ {filename}")
        else:
            print(f"❌ {filename} - NO ENCONTRADO")
            all_ok = False
    
    return all_ok

def check_permissions():
    """Verifica permisos de escritura"""
    print_header("VERIFICANDO PERMISOS")
    
    import os
    
    directories_to_check = ['.', 'reports', 'logs']
    all_ok = True
    
    for directory in directories_to_check:
        # Crear directorio si no existe
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"✅ {directory}/ - Creado correctamente")
            except Exception as e:
                print(f"❌ {directory}/ - Error al crear: {e}")
                all_ok = False
        else:
            # Verificar escritura
            if os.access(directory, os.W_OK):
                print(f"✅ {directory}/ - Permisos de escritura OK")
            else:
                print(f"❌ {directory}/ - Sin permisos de escritura")
                all_ok = False
    
    return all_ok

def run_diagnostics():
    """Ejecuta todos los diagnósticos"""
    print("\n")
    print("╔═══════════════════════════════════════════════╗")
    print("║   NetAuditBot - Diagnóstico del Sistema      ║")
    print("╚═══════════════════════════════════════════════╝")
    
    results = {
        'python': check_python(),
        'nmap': check_nmap(),
        'modules': check_python_modules(),
        'files': check_files(),
        'permissions': check_permissions()
    }
    
    # Resumen final
    print_header("RESUMEN DE DIAGNÓSTICO")
    
    total_checks = len(results)
    passed_checks = sum(results.values())
    
    for check_name, result in results.items():
        status = "✅ OK" if result else "❌ FALLO"
        print(f"{check_name.upper():15s}: {status}")
    
    print(f"\nResultado: {passed_checks}/{total_checks} verificaciones pasadas")
    
    if all(results.values()):
        print("\n🎉 ¡EXCELENTE! Todos los requisitos están satisfechos.")
        print("   Puedes ejecutar NetAuditBot sin problemas.")
        print("\n   Uso: python netauditbot.py <red>")
        print("   Ejemplo: python netauditbot.py 192.168.1.0/24")
        return 0
    else:
        print("\n⚠️  ATENCIÓN: Algunos requisitos no están satisfechos.")
        print("   Por favor, revisa los errores arriba y corrígelos.")
        print("\n   Pasos recomendados:")
        
        if not results['nmap']:
            print("   1. Instalar Nmap")
        if not results['modules']:
            print("   2. Ejecutar: pip install -r requirements.txt")
        if not results['files']:
            print("   3. Verificar que todos los archivos .py estén presentes")
        if not results['permissions']:
            print("   4. Verificar permisos de escritura en la carpeta")
        
        return 1

def main():
    """Función principal"""
    try:
        exit_code = run_diagnostics()
        print("\n")
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Diagnóstico interrumpido por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error durante el diagnóstico: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()