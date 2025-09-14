#!/usr/bin/env python3
"""
Installation validation script for PIoC platform.
Checks if all dependencies are properly installed and configured.
"""

import sys
import importlib
import subprocess
from pathlib import Path
import platform

def check_python_version():
    """Check if Python version is compatible."""
    print("🐍 Checking Python version...")
    version = sys.version_info
    
    if version.major == 3 and version.minor >= 11:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Requires Python 3.11+")
        return False

def check_dependencies():
    """Check if all required dependencies are installed."""
    print("\n📦 Checking dependencies...")
    
    # Package name -> import name mapping
    required_packages = {
        'fastapi': 'fastapi',
        'uvicorn': 'uvicorn', 
        'streamlit': 'streamlit',
        'pandas': 'pandas',
        'plotly': 'plotly',
        'sqlalchemy': 'sqlalchemy',
        'pydantic': 'pydantic',
        'cryptography': 'cryptography',
        'requests': 'requests',
        'aiohttp': 'aiohttp',
        'dnspython': 'dns',  # Package name vs import name
        'validators': 'validators',
        'python-dotenv': 'dotenv',  # Package name vs import name
        'rich': 'rich',
        'typer': 'typer',
        'aiofiles': 'aiofiles'
    }
    
    missing_packages = []
    
    for package_name, import_name in required_packages.items():
        try:
            importlib.import_module(import_name)
            print(f"✅ {package_name}")
        except ImportError:
            print(f"❌ {package_name} - Not installed")
            missing_packages.append(package_name)
    
    return len(missing_packages) == 0, missing_packages

def check_project_structure():
    """Check if project structure is correct."""
    print("\n📁 Checking project structure...")
    
    required_files = [
        'requirements/requirements.txt',
        'requirements/requirements.in',
        'src/pioc/api_server.py',
        'src/pioc/gui_app.py',
        'launcher.py',
        'core/config.py',
        'src/pioc/models.py',
        'src/pioc/indicator_processor.py',
        'src/pioc/health_checker.py',
        'src/pioc/utils.py',
        'src/pioc/auth.py',
        'run.py'
    ]
    
    missing_files = []
    
    for file in required_files:
        if Path(file).exists():
            print(f"✅ {file}")
        else:
            print(f"❌ {file} - Missing")
            missing_files.append(file)
    
    return len(missing_files) == 0, missing_files

def check_directories():
    """Check if required directories exist."""
    print("\n📂 Checking directories...")
    
    required_dirs = [
        'exports',
        'temp', 
        'uploads'
    ]
    
    for directory in required_dirs:
        dir_path = Path(directory)
        if dir_path.exists():
            print(f"✅ {directory}/")
        else:
            print(f"⚠️  {directory}/ - Will be created automatically")
            try:
                dir_path.mkdir(exist_ok=True)
                print(f"✅ Created {directory}/")
            except Exception as e:
                print(f"❌ Failed to create {directory}/: {e}")

def test_imports():
    """Test importing main modules."""
    print("\n🔬 Testing module imports...")
    
    # Add current directory to Python path for imports
    import sys
    from pathlib import Path
    current_dir = Path.cwd()
    if str(current_dir) not in sys.path:
        sys.path.insert(0, str(current_dir))
    
    modules_to_test = [
        ('core.config', 'Configuration'),
        ('src.pioc.models', 'Database models'),
        ('src.pioc.utils', 'Utilities'),
        ('src.pioc.indicator_processor', 'Indicator processor'),
        ('src.pioc.health_checker', 'Health checker'),
        ('src.pioc.auth', 'Authentication')
    ]
    
    failed_imports = []
    
    for module, description in modules_to_test:
        try:
            importlib.import_module(module)
            print(f"✅ {module} - {description}")
        except Exception as e:
            print(f"❌ {module} - Failed: {str(e)[:60]}...")
            failed_imports.append(module)
    
    return len(failed_imports) == 0, failed_imports

def check_pip_tools():
    """Check if pip-tools is available for development."""
    print("\n🔧 Checking development tools...")
    
    try:
        import pip_tools
        print("✅ pip-tools - Available for dependency management")
        return True
    except ImportError:
        print("⚠️  pip-tools - Not installed (optional for users)")
        print("   Install with: pip install pip-tools")
        return False

def main():
    """Run all validation checks."""
    print("🚀 PIoC Installation Validation")
    print("=" * 50)
    
    all_checks_passed = True
    
    # Basic checks
    if not check_python_version():
        all_checks_passed = False
    
    deps_ok, missing_deps = check_dependencies()
    if not deps_ok:
        all_checks_passed = False
    
    structure_ok, missing_files = check_project_structure()
    if not structure_ok:
        all_checks_passed = False
    
    check_directories()
    
    imports_ok, failed_imports = test_imports()
    if not imports_ok:
        all_checks_passed = False
    
    check_pip_tools()
    
    # Summary
    print("\n" + "=" * 50)
    if all_checks_passed:
        print("🎉 All checks passed! PIoC is ready to run.")
        print("\nNext steps:")
        print("1. Run: python launcher.py")
        print("2. Choose your preferred mode (GUI, API, or Both)")
        print("3. Access the application:")
        print("   - GUI: http://localhost:8501")
        print("   - API: http://localhost:8000")
        print("   - API Docs: http://localhost:8000/docs")
    else:
        print("❌ Some checks failed. Please fix the issues above.")
        
        if missing_deps:
            print(f"\n📦 Install missing dependencies:")
            print(f"pip install -r requirements.txt")
        
        if missing_files:
            print(f"\n📁 Missing files: {', '.join(missing_files)}")
            print("Make sure you've cloned the complete repository.")
        
        if failed_imports:
            print(f"\n🔬 Import failures: {', '.join(failed_imports)}")
            print("This might indicate missing dependencies or configuration issues.")
    
    print(f"\n💻 System Info:")
    print(f"   OS: {platform.system()} {platform.release()}")
    print(f"   Python: {sys.version}")
    print(f"   Platform: {platform.platform()}")

if __name__ == "__main__":
    main()
