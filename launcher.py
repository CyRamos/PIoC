#!/usr/bin/env python3
"""
PloC Platform Launcher
Easy startup script for the Pretty IoC platform.
"""

import sys
import subprocess
import argparse
import time
import os
from pathlib import Path
from typing import Optional

def ensure_utf8_stdout():
    """Attempt to force UTF-8 stdout to avoid UnicodeEncodeError on Windows consoles.

    Uses ``sys.stdout.reconfigure`` when available (Python 3.7+) to switch the
    console encoding to UTF‑8 so printing non‑ASCII characters does not fail.
    """
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        # Fallback: rely on ASCII-safe prints
        pass

def get_python_executable() -> str:
    """Return the Python executable to use for running child tools.

    Prefers the local virtual environment at ``.venv/Scripts/python.exe`` when
    present so that all dependencies (fastapi, uvicorn, streamlit,
    python-multipart, etc.) are resolved from the project environment.
    """
    venv_python = Path('.venv') / 'Scripts' / 'python.exe'
    if venv_python.exists():
        return str(venv_python)
    return sys.executable

def _module_available(py_exec: str, module_name: str) -> bool:
    """Return True if ``module_name`` is importable by ``py_exec``.

    Parameters
    ----------
    py_exec: str
        Absolute path to the Python interpreter to test.
    module_name: str
        The name of the module to import (e.g., ``"fastapi"``).
    """
    try:
        result = subprocess.run([
            py_exec, '-c', f"import {module_name}; print('OK')"
        ], capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False

def check_dependencies():
    """Check if required dependencies are installed for the selected interpreter.

    Returns
    -------
    bool
        True if all required top-level modules can be imported, False otherwise.
    """
    required_packages = [
        'streamlit', 'fastapi', 'uvicorn', 'pandas', 'sqlalchemy', 'multipart'
    ]
    py_exec = get_python_executable()
    missing_packages = [pkg for pkg in required_packages if not _module_available(py_exec, pkg)]

    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("📦 Install with: pip install -r requirements/requirements.txt")
        return False
    
    print("✅ All dependencies are installed")
    return True

def setup_environment(disable_auth: bool = False):
    """Setup environment variables prior to launching services.

    Parameters
    ----------
    disable_auth: bool
        When True, disables GUI authentication (development only).
    """
    env_vars = {}
    
    if disable_auth:
        print("🔓 Authentication disabled for development")
        env_vars['CTI_REQUIRE_AUTH'] = 'false'
    
    # Set environment variables
    for key, value in env_vars.items():
        os.environ[key] = value
    
    return env_vars

def launch_gui(port: int = 8501, disable_auth: bool = False):
    """Launch the Streamlit GUI application on the given ``port``.

    Uses the preferred Python interpreter (local ``.venv`` when available).
    """
    # Check for Render environment PORT
    render_port = os.environ.get('PORT')
    if render_port:
        port = int(render_port)
        print(f"🔧 Using Render PORT environment variable: {port}")
    
    print(f"🚀 Starting CTI GUI on port {port}...")
    
    # Setup environment
    setup_environment(disable_auth)
    
    try:
        py_exec = get_python_executable()
        
        # Determine host based on environment
        host = "0.0.0.0" if os.environ.get('PORT') else "127.0.0.1"
        
        cmd = [
            py_exec, "-m", "streamlit", "run", "src/pioc/gui_app.py",
            "--server.port", str(port),
            "--server.address", host,
            "--server.headless", "true",
            "--browser.gatherUsageStats", "false"
        ]
        
        if os.environ.get('PORT'):
            print(f"📱 GUI will be available at: https://pioc-platform.onrender.com")
        else:
            print(f"📱 GUI will be available at: http://localhost:{port}")
        
        if not disable_auth:
            print("🔐 Authentication required - you'll need to enter your email")
        else:
            print("🔓 Authentication disabled - direct access available")
        
        subprocess.run(cmd)
        
    except KeyboardInterrupt:
        print("\n👋 GUI application stopped")
    except Exception as e:
        print(f"❌ Error starting GUI: {str(e)}")

def launch_api(port: int = 8000):
    """Launch the FastAPI server on the given ``port`` using Uvicorn."""
    # Check for Render environment PORT
    render_port = os.environ.get('PORT')
    if render_port:
        port = int(render_port)
        print(f"🔧 Using Render PORT environment variable: {port}")
    
    print(f"🚀 Starting CTI API on port {port}...")
    
    try:
        py_exec = get_python_executable()
        cmd = [
            py_exec, "-m", "uvicorn", "src.pioc.api_server:app",
            "--host", "0.0.0.0",
            "--port", str(port),
            "--reload"
        ]
        
        print(f"🔗 API will be available at: http://localhost:{port}")
        print(f"📚 API docs at: http://localhost:{port}/docs")
        
        subprocess.run(cmd)
        
    except KeyboardInterrupt:
        print("\n👋 API server stopped")
    except Exception as e:
        print(f"❌ Error starting API: {str(e)}")

def launch_both(gui_port: int = 8501, api_port: int = 8000, disable_auth: bool = False):
    """Launch GUI and API concurrently in background threads."""
    print("🚀 Starting both GUI and API...")
    
    # Check if we're in a Render environment (PORT env var exists)
    render_port = os.environ.get('PORT')
    if render_port:
        # In Render environment, use the PORT for API and disable GUI for now
        api_port = int(render_port)
        print(f"🔧 Render environment detected - using PORT {api_port} for API")
        # For Render deployment, we'll only run the API
        launch_api(api_port)
        return
    
    # Setup environment
    setup_environment(disable_auth)
    
    try:
        import threading
        
        def run_gui():
            py_exec = get_python_executable()
            cmd = [
                py_exec, "-m", "streamlit", "run", "src/pioc/gui_app.py",
                "--server.port", str(gui_port),
                "--server.headless", "true",
                "--browser.gatherUsageStats", "false"
            ]
            subprocess.run(cmd)
        
        def run_api():
            py_exec = get_python_executable()
            cmd = [
                py_exec, "-m", "uvicorn", "src.pioc.api_server:app",
                "--host", "0.0.0.0",
                "--port", str(api_port),
                "--reload"
            ]
            subprocess.run(cmd)
        
        # Start both in separate threads
        gui_thread = threading.Thread(target=run_gui, daemon=True)
        api_thread = threading.Thread(target=run_api, daemon=True)
        
        gui_thread.start()
        time.sleep(2)  # Give GUI a head start
        api_thread.start()
        
        print(f"📱 GUI available at: http://localhost:{gui_port}")
        print(f"🔗 API available at: http://localhost:{api_port}")
        print(f"📚 API docs at: http://localhost:{api_port}/docs")
        
        if not disable_auth:
            print("🔐 Authentication required for GUI")
        else:
            print("🔓 Authentication disabled for GUI")
        
        print("\n⏹️  Press Ctrl+C to stop both services")
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n👋 Stopping all services...")
            
    except Exception as e:
        print(f"❌ Error starting services: {str(e)}")

def process_file(file_path: str, source_name: Optional[str] = None):
    """Process a single file through the indicator pipeline and print a summary."""
    print(f"📁 Processing file: {file_path}")
    
    try:
        from indicator_processor import IndicatorProcessor
        
        processor = IndicatorProcessor()
        result = processor.process_file(Path(file_path), source_name or file_path)
        
        if result.get('success'):
            print(f"✅ Successfully processed {result.get('processed_indicators', 0)} indicators")
            print(f"💾 Stored {result.get('stored_indicators', 0)} new indicators")
            print(f"⏱️  Processing time: {result.get('processing_time_seconds', 0):.2f} seconds")
        else:
            print(f"❌ Processing failed: {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"❌ Error processing file: {str(e)}")

def show_status():
    """Print a quick system status report (deps, DB, config, files)."""
    print("🔍 PloC Platform Status")
    print("=" * 50)
    
    # Check dependencies
    deps_ok = check_dependencies()
    
    # Check database
    try:
        from models import SessionLocal
        from sqlalchemy import text
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
        print("✅ Database: Connected")
    except Exception as e:
        print(f"❌ Database: Error - {str(e)}")
    
    # Check configuration
    try:
        from config import app_config, security_config
        print(f"✅ Configuration: Loaded")
        print(f"   - App: {app_config.APP_NAME} v{app_config.APP_VERSION}")
        print(f"   - Debug: {app_config.DEBUG}")
    except Exception as e:
        print(f"❌ Configuration: Error - {str(e)}")
    
    # Check file structure
    required_files = ['src/pioc/gui_app.py', 'src/pioc/api_server.py', 'core/config.py', 'src/pioc/models.py']
    for file in required_files:
        if Path(file).exists():
            print(f"✅ {file}: Found")
        else:
            print(f"❌ {file}: Missing")

def main():
    """Main launcher entrypoint. Supports GUI/API/Both/Process/Status modes."""
    ensure_utf8_stdout()
    parser = argparse.ArgumentParser(description="PloC Platform Launcher")
    parser.add_argument('command', nargs='?', choices=['gui', 'api', 'both', 'process', 'status'], 
                       help='Command to run')
    parser.add_argument('--gui-port', type=int, default=8501, help='GUI port (default: 8501)')
    parser.add_argument('--api-port', type=int, default=8000, help='API port (default: 8000)')
    parser.add_argument('--file', type=str, help='File to process (for process command)')
    parser.add_argument('--source', type=str, help='Source name for file processing')
    parser.add_argument('--no-auth', action='store_true', help='Disable authentication (development only)')
    
    args = parser.parse_args()
    
    try:
        print("🛡️  PloC Platform Launcher")
    except Exception:
        print("PloC Platform Launcher")
    print("=" * 50)

    # Interactive menu if no command provided
    if not args.command:
        print("Select mode to run:")
        print("  1) GUI only")
        print("  2) API only")
        print("  3) Both GUI and API")
        print("  4) Process a file")
        print("  5) Status check")
        choice = input("Enter choice [1-5]: ").strip()
        mapping = {
            '1': 'gui', '2': 'api', '3': 'both', '4': 'process', '5': 'status'
        }
        args.command = mapping.get(choice)
        if not args.command:
            print("Invalid choice. Exiting.")
            return

    if args.command == 'gui':
        if not check_dependencies():
            return
        launch_gui(args.gui_port, args.no_auth)
        
    elif args.command == 'api':
        if not check_dependencies():
            return
        launch_api(args.api_port)
        
    elif args.command == 'both':
        if not check_dependencies():
            return
        launch_both(args.gui_port, args.api_port, args.no_auth)
        
    elif args.command == 'process':
        if not args.file:
            print("❌ --file argument required for process command")
            return
        if not check_dependencies():
            return
        process_file(args.file, args.source)
        
    elif args.command == 'status':
        show_status()

if __name__ == "__main__":
    main() 