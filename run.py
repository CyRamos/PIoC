#!/usr/bin/env python3
"""
PIoC - Pretty IoC Cyber Threat Intelligence Platform
Main entry point for the application.

Usage:
    python run.py          # Interactive launcher with menu
    python run.py --setup  # Run initial setup
    python run.py --gui     # Launch GUI directly
    python run.py --api     # Launch API directly
    python run.py --both    # Launch both GUI and API
"""

import sys
import argparse
from pathlib import Path

# Ensure we can import our modules
sys.path.append(str(Path(__file__).parent))

def main():
    """Main entry point with command line arguments."""
    parser = argparse.ArgumentParser(
        description="PIoC - Pretty IoC Cyber Threat Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                 # Interactive launcher menu
  python run.py --setup         # Run first-time setup
  python run.py --gui           # Launch Streamlit GUI
  python run.py --api           # Launch FastAPI backend
  python run.py --both          # Launch both GUI and API
  python run.py --validate      # Validate installation
        """
    )
    
    parser.add_argument('--setup', action='store_true', 
                       help='Run first-time setup')
    parser.add_argument('--gui', action='store_true',
                       help='Launch Streamlit GUI directly')
    parser.add_argument('--api', action='store_true',
                       help='Launch FastAPI backend directly')
    parser.add_argument('--both', action='store_true',
                       help='Launch both GUI and API')
    parser.add_argument('--validate', action='store_true',
                       help='Validate installation')
    
    args = parser.parse_args()
    
    # Import launcher after path setup
    from launcher import main as launcher_main, launch_gui, launch_api, launch_both
    
    if args.setup:
        print("🔧 Running PIoC setup...")
        import subprocess
        result = subprocess.run([sys.executable, "scripts/setup.py"], cwd=Path(__file__).parent)
        sys.exit(result.returncode)
    elif args.validate:
        print("🔍 Validating PIoC installation...")
        import subprocess
        result = subprocess.run([sys.executable, "scripts/validate_installation.py"], cwd=Path(__file__).parent)
        sys.exit(result.returncode)
    elif args.gui:
        print("🌐 Launching PIoC GUI...")
        launch_gui()
    elif args.api:
        print("⚡ Launching PIoC API...")
        launch_api()
    elif args.both:
        print("🚀 Launching PIoC (GUI + API)...")
        launch_both()
    else:
        # Default: Interactive launcher
        print("🛡️  Welcome to PIoC - Pretty IoC Platform")
        print("=" * 50)
        launcher_main()

if __name__ == "__main__":
    main()
