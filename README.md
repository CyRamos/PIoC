# 🛡️ PIoC - Pretty IoC Platform

> **Cyber Threat Intelligence Platform with GUI and API**

## 🚀 Quick Start

```bash
# 1. Clone and enter directory
git clone https://github.com/CyRamos/PIoC
cd PIoC

# 2. Setup (first time only)
python run.py --setup

# 3. Run the platform
python run.py
```

## 📖 Documentation

- **[📋 Full README](docs/README.md)** - Complete documentation
- **[⚡ Quick Start](docs/QUICKSTART.md)** - Fast setup guide  
- **[🔧 Installation](docs/INSTALLATION.md)** - Detailed setup
- **[🛠️ Development](docs/DEVELOPMENT.md)** - For contributors

## 🎯 Entry Points

| Command | Purpose |
|---------|---------|
| `python run.py` | Interactive launcher menu |
| `python run.py --setup` | First-time setup |
| `python run.py --gui` | Launch GUI only |
| `python run.py --api` | Launch API only |
| `python run.py --both` | Launch both |
| `python run.py --validate` | Check installation |

## 🏗️ Project Structure

```
PIoC/
├── run.py              # 🎯 Main entry point
├── src/pioc/           # Core application  
├── core/               # Configuration
├── requirements/       # Dependencies
├── scripts/           # Setup utilities
├── docs/              # Documentation
└── data/              # Sample data
```

## ⚡ Quick Commands

```bash
# First time setup
python run.py --setup

# Launch with menu
python run.py

# Direct launches
python run.py --gui     # GUI at http://localhost:8501
python run.py --api     # API at http://localhost:8000
python run.py --both    # Both services

# Validate everything works
python run.py --validate
```

## 🔍 What's PIoC?

A comprehensive **Cyber Threat Intelligence (CTI)** platform featuring:

- 🌐 **Web GUI** (Streamlit) - User-friendly interface
- ⚡ **REST API** (FastAPI) - Programmatic access  
- 📊 **Indicator Management** - IOCs, IPs, URLs, hashes
- 🔍 **Search & Analytics** - Advanced filtering
- 📤 **Import/Export** - Bulk operations
- 🔒 **Security** - Authentication & validation

## 🗃️ Database

PIoC uses **SQLite** as its default database engine for simplicity and portability:

- **Database Type**: SQLite (file-based, serverless)
- **Default Location**: `cti_database.db` (auto-created on first run)
- **Schema**: Automatically initialized with tables for indicators, health checks, audit logs, and tags
- **Fresh Install**: Each fresh clone gets a clean database - no existing data is included
- **Migration**: Database schema is created automatically during first setup

### 🔧 Custom Database Configuration

PIoC supports connecting to external databases (network shares, remote servers):

- **Supported Types**: SQLite, PostgreSQL, MySQL, MariaDB
- **Network Support**: Connect to databases on network shares or remote servers
- **Configuration**: Use the Settings page in the GUI to configure custom database URLs
- **Connectivity Testing**: Built-in connectivity testing with real-time status
- **Security**: Passwords are masked in the UI for security

**Example Database URLs:**
```bash
# Local SQLite
sqlite:///C:/path/to/database.db

# Network Share SQLite  
sqlite:////network/share/database.db

# PostgreSQL
postgresql://user:password@server:5432/database

# MySQL
mysql://user:password@server:3306/database
```

The application will create a new, empty database file on first run, ensuring each installation starts with a clean slate.

## 📄 License

See [LICENSE](LICENSE) for details.

---

**Ready? Start with: `python run.py --setup`** 🚀