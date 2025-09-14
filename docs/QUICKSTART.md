# CTI Platform - Quick Start Guide

Get up and running with the CTI (Cyber Threat Intelligence) Platform in 5 minutes!

## 🚀 Quick Installation

### 1. Install Dependencies
```bash
# Install with flexible version requirements (recommended)
pip install -r requirements-flexible.txt

# OR install with exact versions (if you encounter issues)
pip install -r requirements.txt
```

### 2. Initialize Database
```bash
python -c "from models import init_db; init_db()"
```

### 3. Launch the Platform

#### Option A: GUI Only (with authentication)
```bash
python launcher.py gui
```
- Opens web interface at http://localhost:8501
- Requires email authentication
- Supports cyterous.com integration

#### Option B: GUI Only (development mode - no auth)
```bash
python launcher.py gui --no-auth
```
- Opens web interface at http://localhost:8501
- **No authentication required** - direct access
- Perfect for development and testing

#### Option C: Both GUI and API
```bash
python launcher.py both --no-auth
```
- GUI at http://localhost:8501 (no auth)
- API at http://localhost:8000
- API docs at http://localhost:8000/docs

## 🔐 Authentication Options

### Development Mode (No Authentication)
```bash
# Quick access without email
python launcher.py gui --no-auth
```

### Production Mode (Email Authentication)
```bash
# Requires email authentication
python launcher.py gui
```

**Allowed email domains:**
- cyterous.com
- gmail.com

**Admin emails:**
- admin@cyterous.com

### Cyterous.com Integration
Set environment variables for full integration:
```bash
export CYTEROUS_API_KEY="your-api-key"
export CYTEROUS_API_URL="https://cyterous.com/api"
```

## 📁 Process Sample Data

### Using the GUI
1. Launch: `python launcher.py gui --no-auth`
2. Go to "File Upload" page
3. Upload `sample_iocs.csv`
4. Click "Process Files"

### Using Command Line
```bash
python launcher.py process --file sample_iocs.csv --source "Sample Data"
```

## 🔧 Launcher Commands

```bash
# GUI only
python launcher.py gui [--no-auth] [--gui-port 8501]

# API only  
python launcher.py api [--api-port 8000]

# Both GUI and API
python launcher.py both [--no-auth] [--gui-port 8501] [--api-port 8000]

# Process a file
python launcher.py process --file <path> [--source <name>]

# Check system status
python launcher.py status
```

## 🎯 Quick Test

1. **Start without authentication:**
   ```bash
   python launcher.py gui --no-auth
   ```

2. **Upload sample data:**
   - Go to http://localhost:8501
   - Navigate to "File Upload"
   - Upload `sample_iocs.csv`
   - Process the file

3. **Explore features:**
   - Dashboard: View metrics and charts
   - Indicator Management: Search and manage indicators
   - Health Checks: Monitor indicator health
   - Analytics: View trends and patterns

## 🛠️ Troubleshooting

### Dependencies Issues
```bash
# Check what's missing
python launcher.py status

# Install flexible requirements
pip install -r requirements-flexible.txt
```

### Database Issues
```bash
# Reinitialize database
python -c "from models import init_db; init_db()"
```

### Port Conflicts
```bash
# Use different ports
python launcher.py gui --gui-port 8502
python launcher.py api --api-port 8001
```

### Authentication Issues
```bash
# Disable authentication for development
python launcher.py gui --no-auth
```

## 📊 Sample Data

The platform includes `sample_iocs.csv` with:
- 🌐 IP addresses
- 🔗 URLs and domains  
- 🔒 File hashes
- 📧 Email addresses

Perfect for testing all features!

## 🔗 Next Steps

- **Production Setup:** Configure authentication with your domain
- **API Integration:** Use the REST API for automation
- **Health Monitoring:** Set up automated health checks
- **Data Sources:** Connect your threat intelligence feeds

## 💡 Pro Tips

1. **Development:** Always use `--no-auth` for quick testing
2. **Production:** Set up proper email domains in `config.py`
3. **Integration:** Use the API for automated workflows
4. **Monitoring:** Check the audit logs regularly

---

**Need help?** Check the full [README.md](README.md) or visit [cyterous.com](https://cyterous.com) 