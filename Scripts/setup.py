#!/usr/bin/env python3
"""
PIoC Setup Script
Automated setup for the Pretty IoC Cyber Threat Intelligence platform.
"""

import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    """Print setup banner."""
    print("🛡️  PIoC Setup - Cyber Threat Intelligence Platform")
    print("=" * 60)
    print()

def check_python_version():
    """Check Python version compatibility."""
    print("🐍 Checking Python version...")
    version = sys.version_info
    
    if version.major == 3 and version.minor >= 11:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro}")
        print("⚠️  PIoC requires Python 3.11 or higher")
        print("📥 Download from: https://python.org/downloads/")
        return False

def install_dependencies():
    """Install project dependencies."""
    print("\n📦 Installing dependencies...")
    
    try:
        # Upgrade pip first
        print("📈 Upgrading pip...")
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                      check=True, capture_output=True)
        
        # Install main dependencies
        print("📥 Installing PIoC dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements/requirements.txt"], 
                      check=True)
        
        print("✅ Dependencies installed successfully!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        print("\n🔧 Manual installation:")
        print("pip install -r requirements/requirements.txt")
        return False

def create_directories():
    """Create necessary directories."""
    print("\n📁 Creating directories...")
    
    directories = ['exports', 'temp', 'uploads']
    
    for directory in directories:
        dir_path = Path(directory)
        if not dir_path.exists():
            dir_path.mkdir(exist_ok=True)
            print(f"✅ Created {directory}/")
        else:
            print(f"✅ {directory}/ already exists")

def run_validation():
    """Run installation validation."""
    print("\n🔍 Validating installation...")
    
    try:
        result = subprocess.run([sys.executable, "scripts/validate_installation.py"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Validation passed!")
            return True
        else:
            print("⚠️  Validation found issues:")
            print(result.stdout)
            return False
            
    except Exception as e:
        print(f"⚠️  Could not run validation: {e}")
        return False

def show_next_steps():
    """Show next steps for the user."""
    print("\n🎉 Setup Complete!")
    print("=" * 40)
    print()
    print("🚀 Next Steps:")
    print("1. Run the application:")
    print("   python launcher.py")
    print()
    print("2. Choose your mode:")
    print("   • Option 1: GUI only (Streamlit)")
    print("   • Option 2: API only (FastAPI)")
    print("   • Option 3: Both GUI and API")
    print()
    print("🌐 Access URLs:")
    print("   • GUI: http://localhost:8501")
    print("   • API: http://localhost:8000")
    print("   • API Docs: http://localhost:8000/docs")
    print()
    print("🔑 Authentication:")
    print("   • Email: Use gmail.com or cyterous.com")
    print("   • API Token: demo-token")
    print()
    print("📚 Documentation:")
    print("   • Installation: INSTALLATION.md")
    print("   • Development: DEVELOPMENT.md")
    print("   • Features: DIFF_FUNCTIONALITY.md")

def main():
    """Main setup function."""
    print_banner()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\n⚠️  Setup completed with warnings.")
        print("Please install dependencies manually and run validation.")
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Validate installation
    validation_passed = run_validation()
    
    # Show next steps
    show_next_steps()
    
    if not validation_passed:
        print("\n⚠️  Setup completed but validation found issues.")
        print("Check the validation output above and fix any problems.")
        sys.exit(1)
    
    print("\n✨ PIoC is ready to use!")

if __name__ == "__main__":
    main()
