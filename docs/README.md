# 🛡️ PIoC - Pretty IoC Cyber Threat Intelligence Platform

A comprehensive platform for managing and analyzing Cyber Threat Intelligence (CTI) indicators with both GUI and API interfaces.

## 🚀 Quick Start

### 🐳 Docker Installation (Recommended)

The easiest way to run PIoC is using Docker:

```bash
# Clone the repository
git clone https://github.com/CyRamos/PIoC
cd PIoC

# Run with Docker Compose (recommended)
docker-compose up -d

# OR build and run manually
docker build -t pioc-platform .
docker run -d -p 8501:8501 -p 8000:8000 --name pioc pioc-platform
```

**Access the platform:**
- 🌐 **GUI**: http://localhost:8501
- ⚡ **API**: http://localhost:8000
- 📚 **API Docs**: http://localhost:8000/docs

### 🐍 Local Python Installation

For development or if you prefer local installation:

#### 1. Installation
```bash
# Clone the repository
git clone https://github.com/CyRamos/PIoC
cd PIoC

# Run setup (installs dependencies and configures environment)
python run.py --setup

# OR install manually:
pip install -r requirements/requirements.txt
```

#### 2. Run the Platform
```bash
# Interactive launcher (recommended for first-time users)
python run.py

# OR launch specific components:
python run.py --gui    # Streamlit GUI only
python run.py --api    # FastAPI backend only
python run.py --both   # Both GUI and API
```

#### 3. Validate Installation
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

## 🐳 Docker Deployment

### Docker Compose (Production Ready)

The `docker-compose.yml` file provides a complete deployment setup:

```bash
# Start the platform
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the platform
docker-compose down

# Update and restart
docker-compose pull
docker-compose up -d --force-recreate
```

### Docker Commands

```bash
# Build the image (Python 3.11 - recommended)
docker build -t pioc-platform .

# Build for Python 3.7 (legacy support)
docker build -f Dockerfile.python37 -t pioc-platform-py37 .

# Run container with custom settings
docker run -d \
  --name pioc-platform \
  -p 8501:8501 \
  -p 8000:8000 \
  -e CTI_REQUIRE_AUTH=false \
  -e CTI_DEBUG=true \
  -v pioc_data:/app/data \
  pioc-platform

# View container logs
docker logs -f pioc-platform

# Access container shell
docker exec -it pioc-platform bash
```

### Multi-Python Version Support

For different Python versions:

```bash
# Python 3.11 (recommended)
docker-compose --profile python311 up -d
# Access: GUI http://localhost:8501, API http://localhost:8000

# Python 3.7 (legacy support)
docker-compose --profile python37 -f docker-compose.multi-python.yml up -d
# Access: GUI http://localhost:8502, API http://localhost:8001
```

### Data Persistence

Docker volumes are used to persist important data:
- `pioc_data`: Application database and data files
- `pioc_exports`: Exported files and reports
- `pioc_uploads`: Uploaded indicator files
- `pioc_logs`: Application logs

### Testing Docker Setup

To verify your Docker installation works correctly:

```bash
# Linux/macOS
chmod +x test-docker.sh
./test-docker.sh

# Windows
test-docker.bat
```

The test script will:
1. Build the Docker image
2. Start a test container
3. Verify services are running
4. Test Docker Compose (if available)
5. Clean up test containers

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

### Docker Deployment
- **Docker**: 20.10+ 
- **Docker Compose**: 2.0+
- **Memory**: 2GB+ RAM
- **Storage**: 2GB+ free space
- **Network**: Internet for threat intelligence feeds

### Local Python Installation
- **Python**: 3.7+ (minimum), 3.11+ (recommended)
- **Memory**: 2GB+ RAM
- **Storage**: 1GB+ free space
- **Network**: Internet for threat intelligence feeds

**Note**: Python 2.7 is **NOT supported** due to modern dependencies (FastAPI, Streamlit, Pydantic v2) that require Python 3.7+.

📋 **See [PYTHON_COMPATIBILITY.md](PYTHON_COMPATIBILITY.md) for detailed version support information.**

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