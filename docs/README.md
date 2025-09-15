# 🛡️ PIoC - Pretty IoC Cyber Threat Intelligence Platform

A comprehensive platform for managing and analyzing Cyber Threat Intelligence (CTI) indicators with both GUI and API interfaces.

## 🚀 Quick Start

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/CyRamos/PIoC
cd PIoC

# Run setup (installs dependencies and configures environment)
python run.py --setup

# OR install manually:
pip install -r requirements/requirements.txt
```

### 2. Run the Platform
```bash
# Interactive launcher (recommended for first-time users)
python run.py

# OR launch specific components:
python run.py --gui    # Streamlit GUI only
python run.py --api    # FastAPI backend only
python run.py --both   # Both GUI and API
```

### 3. Validate Installation
```bash
python run.py --validate
```

## 📁 Project Structure

```
PIoC/
├── run.py                    # 🎯 Main entry point
├── launcher.py               # Interactive launcher with menu
│
├── src/pioc/                # Core application
│   ├── api_server.py        # FastAPI backend
│   ├── gui_app.py           # Streamlit frontend
│   ├── models.py            # Database models
│   ├── auth.py              # Authentication
│   ├── utils.py             # Utilities
│   ├── indicator_processor.py
│   └── health_checker.py
│
├── core/                    # Configuration
│   └── config.py            # Application config
│
├── requirements/            # Dependencies
│   ├── requirements.in      # High-level deps
│   ├── requirements.txt     # Locked versions
│   ├── requirements-dev.in  # Development deps
│   └── requirements-dev.txt
│
├── scripts/                 # Utilities
│   ├── setup.py            # First-time setup
│   └── validate_installation.py
│
├── docs/                    # Documentation
│   ├── README.md            # This file
│   ├── INSTALLATION.md      # Detailed setup
│   ├── DEVELOPMENT.md       # Development guide
│   └── QUICKSTART.md        # Quick reference
│
├── data/                    # Sample data & exports
├── tests/                   # Test files
├── temp/                    # Temporary files
└── uploads/                 # File uploads
```

## 🎛️ Usage

### First Time Users

1. **Setup**: `python run.py --setup`
2. **Run**: `python run.py` (choose option from menu)
3. **Access GUI**: Open browser to displayed URL (usually http://localhost:8501)
4. **Access API**: API docs at http://localhost:8000/docs

### Regular Usage

- **Quick GUI**: `python run.py --gui`
- **Quick API**: `python run.py --api`  
- **Full Platform**: `python run.py --both`

### API Endpoints

The FastAPI backend provides REST endpoints for:
- 📊 **Indicators**: `/api/v1/indicators` - Manage IOCs
- 🔍 **Search**: `/api/v1/search` - Search indicators
- 📤 **Export**: `/api/v1/export` - Export data
- 💾 **Upload**: `/api/v1/upload` - Bulk upload
- 🔍 **Health**: `/health` - System status

**API Documentation**: http://localhost:8000/docs

### GUI Features

The Streamlit interface provides:
- 📊 **Dashboard**: Overview and statistics
- 🔍 **Search & Filter**: Find indicators
- 📤 **Import/Export**: Bulk operations
- 📈 **Visualization**: Charts and graphs
- ⚙️ **Settings**: Configuration
- 🔒 **Security**: User management

## 🔧 Configuration

### Environment Variables
```bash
CTI_REQUIRE_AUTH=true    # Enable authentication
CTI_DEBUG=false          # Debug mode
CTI_LOG_LEVEL=INFO      # Logging level
```

### Database
- SQLite database: `cti_database.db`
- Automatic schema creation
- Backup and restore utilities

## 🛠️ Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for:
- Development setup
- Contributing guidelines
- Testing procedures
- API development

## 📋 Requirements

- **Python**: 3.11+ (recommended)
- **Memory**: 2GB+ RAM
- **Storage**: 1GB+ free space
- **Network**: Internet for threat intelligence feeds

## 🔒 Security

- Token-based authentication
- Rate limiting
- Input validation
- Audit logging
- Data encryption

## 📞 Support

- **Documentation**: See `docs/` folder
- **Issues**: Create GitHub issues
- **Logs**: Check `cti_application.log`

## 📄 License

See [LICENSE](../LICENSE) file for details.

---

**🚀 Ready to start? Run `python run.py --setup` and follow the guide!**