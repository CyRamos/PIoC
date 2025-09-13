# CTI Threat Intelligence Platform

A comprehensive Cyber Threat Intelligence (CTI) platform implementing R.A.I.L.G.U.A.R.D security principles for secure indicator management, processing, and analysis.

## 🛡️ Features

### Core Features
- **File Processing**: Support for CSV, JSON, TXT, and XML files containing indicators
- **Indicator Normalization**: Automatic defanging and normalization of URLs, IPs, domains, hashes, and emails
- **Health Checking**: Automated reputation and accessibility checks for indicators
- **Duplicate Detection**: Prevents duplicate indicators in the database
- **GUI Management**: User-friendly Streamlit interface for operations
- **REST API**: FastAPI backend for programmatic access
- **Comprehensive Analytics**: Visual dashboards and trend analysis

### Security Features (R.A.I.L.G.U.A.R.D)
- **R**ate Limiting: Configurable request rate limiting (60 req/min default)
- **A**uthentication: Token-based authentication with role-based access
- **I**nput Validation: File content validation and input sanitization
- **L**ogging: Comprehensive audit logging and system monitoring
- **G**eneral Security: Encryption, secure file handling, and hash validation
- **U**ser Access Control: Role-based permissions (admin/analyst)
- **A**udit & Monitoring: Complete audit trail and compliance logging
- **R**isk Management: Malware scanning and suspicious file quarantine
- **D**ata Protection: Encryption at rest and configurable data retention

## 📁 Project Structure

```
CTI-Platform/
├── main.py                 # Legacy indicator parser (existing)
├── sample_iocs.csv         # Sample indicators file (existing)
├── requirements.txt        # Python dependencies
├── config.py              # Configuration and security settings
├── models.py              # Database models and schemas
├── indicator_processor.py  # Core indicator processing logic
├── health_checker.py      # Health checking functionality
├── utils.py               # Security utilities and helpers
├── gui_app.py             # Streamlit GUI application
├── api_server.py          # FastAPI REST API server
├── README.md              # This documentation
├── uploads/               # Upload directory (created automatically)
├── temp/                  # Temporary files directory
└── exports/               # Export directory
```

## 🚀 Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Setup

1. **Clone/Download the project files to your workspace**

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Environment Configuration (Optional):**
Create a `.env` file for custom configuration:
```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///cti_database.db
DEBUG=True
LOG_LEVEL=INFO
ADMIN_EMAIL=admin@yourorg.com
```

4. **Initialize the database:**
The database will be created automatically on first run.

## 🖥️ Usage

### Recommended: Interactive Launcher

Start from a single menu that lets you run GUI, API, or Both. The launcher automatically prefers the local virtual environment at `.venv`.

PowerShell (Windows):
```powershell
cd E:\Code\PIoC
.\.venv\Scripts\Activate.ps1     # activate the local venv
python start.py                    # open interactive menu
```

When prompted, choose:
- `1` → GUI only
- `2` → API only
- `3` → Both (GUI + API)

Non‑interactive equivalents:
```powershell
# GUI only
python launcher.py gui --gui-port 8501

# API only
python launcher.py api --api-port 8000

# Both
python launcher.py both --gui-port 8501 --api-port 8000

# Development (disable GUI auth)
python launcher.py gui --no-auth
python launcher.py both --no-auth
```

### API Documentation

The built-in OpenAPI docs are automatically available when the API server starts:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

Notes:
- If your console has Unicode/emoji encoding issues, run with UTF‑8:
  ```powershell
  python -X utf8 launcher.py both
  ```
-- Do not run `streamlit run launcher.py` (the launcher is not a Streamlit app).
-- Do not run `streamlit run api_server.py` (that file is a FastAPI app, not Streamlit).

### Running the GUI Application (manual)

Start the Streamlit GUI interface:
```bash
streamlit run gui_app.py
```

The GUI will be available at: http://localhost:8501

#### GUI Features:
- **Dashboard**: Overview of indicators, health checks, and system status
- **File Upload**: Drag-and-drop file processing with progress tracking
- **Indicator Management**: Search, filter, and manage indicators with bulk operations
- **Health Checks**: Monitor indicator reputation and accessibility
- **Analytics**: Visual dashboards with charts and trend analysis
- **Audit Logs**: View system activity and user actions
- **Settings**: System configuration and maintenance tools

### Running the API Server (manual)

Start the FastAPI backend server:
```bash
python api_server.py
```

The API will be available at: http://localhost:8000
API documentation: http://localhost:8000/docs

#### API Endpoints:

**Authentication:**
- Use token `demo-token` for demo access

**Indicators:**
- `GET /api/v1/indicators` - List indicators with filtering
- `GET /api/v1/indicators/{id}` - Get specific indicator
- `POST /api/v1/indicators` - Create new indicator
- `POST /api/v1/indicators/exists` - Check if indicator exists (type inferred)
- `POST /api/v1/indicators/bulk` - Bulk insert/upsert indicators
- `DELETE /api/v1/indicators/{id}` - Delete indicator
- `POST /api/v1/indicators/upload` - Upload file for processing

**Health Checks:**
- `GET /api/v1/health-checks` - List health check results
- `POST /api/v1/health-checks/run` - Run health checks

**Statistics & Monitoring:**
- `GET /api/v1/statistics` - Platform statistics
- `GET /api/v1/audit-logs` - Audit logs
- `POST /api/v1/system/cleanup` - Clean old data (admin only)

#### PowerShell API Examples:

**Note:** The Swagger UI at `/docs` generates Unix-style curl commands. For Windows PowerShell, use these examples:

```powershell
# List indicators
curl -Uri 'http://localhost:8000/api/v1/indicators' -Headers @{'Authorization'='Bearer demo-token'}

# Check if indicator exists
curl -Uri 'http://localhost:8000/api/v1/indicators/exists' -Method POST -Headers @{'Authorization'='Bearer demo-token'; 'Content-Type'='application/json'} -Body '{"value":"192.168.1.1"}'

# Add single indicator
curl -Uri 'http://localhost:8000/api/v1/indicators' -Method POST -Headers @{'Authorization'='Bearer demo-token'; 'Content-Type'='application/json'} -Body '{"value":"malware.com","confidence_score":80,"tlp_level":"RED"}'

# Bulk insert indicators
curl -Uri 'http://localhost:8000/api/v1/indicators/bulk' -Method POST -Headers @{'Authorization'='Bearer demo-token'; 'Content-Type'='application/json'} -Body '{"items":[{"value":"192.168.1.1","confidence_score":80},{"value":"malware.com","tlp_level":"RED"}],"source_name":"api_test"}'

# Get statistics
curl -Uri 'http://localhost:8000/api/v1/statistics' -Headers @{'Authorization'='Bearer demo-token'}

# Health check (no auth needed)
curl -Uri 'http://localhost:8000/health'
```

### Using the Legacy CLI

Process files using the original `main.py`:
```bash
python main.py sample_iocs.csv
```

## 📊 Supported Indicator Types

| Type | Description | Example |
|------|-------------|---------|
| **IP** | IPv4/IPv6 addresses | `192.168.1.1`, `2001:db8::1` |
| **Domain** | Domain names | `example.com`, `malware[.]com` |
| **URL** | Web URLs | `hxxps://example[.]com/path` |
| **Hash** | File hashes (MD5, SHA1, SHA256) | `d41d8cd98f00b204e9800998ecf8427e` |
| **Email** | Email addresses | `user@domain[.]com` |

### Defanging Support
The platform automatically handles common defanging patterns:
- `hxxp`/`hxxps` → `http`/`https`
- `[.]` → `.`
- `|.|` → `.`
- `(.)` → `.`

## 🔧 Configuration

### Security Configuration (`config.py`)

Key security settings:
- `MAX_FILE_SIZE_MB`: Maximum upload file size (50MB default)
- `MAX_REQUESTS_PER_MINUTE`: Rate limiting (60 requests/min default)
- `DATA_RETENTION_DAYS`: Data retention policy (365 days default)
- `ENCRYPT_SENSITIVE_DATA`: Enable encryption for sensitive data
- `AUDIT_LOG_ENABLED`: Enable comprehensive audit logging

### Database Configuration

The platform uses SQLite by default with automatic schema creation. For production, configure a PostgreSQL or MySQL database via `DATABASE_URL`.

### TLP (Traffic Light Protocol) Support

Indicators support TLP classification:
- **WHITE**: No restrictions
- **GREEN**: Community sharing
- **AMBER**: Limited sharing
- **RED**: No sharing

## 🔍 Health Checking

The platform performs automated health checks on indicators:

### IP Address Checks
- DNS reputation list queries (Spamhaus, SpamCop, SORBS, Barracuda)
- Geolocation analysis
- Private IP detection

### Domain Checks
- DNS resolution verification
- WHOIS information analysis (placeholder)
- Suspicious pattern detection
- Homograph attack detection

### URL Checks
- Accessibility verification
- Suspicious pattern analysis
- URL shortener detection
- Length and structure analysis

## 📈 Analytics

The platform provides comprehensive analytics:
- **Timeline Charts**: Indicator additions over time
- **Distribution Charts**: By type, source, and TLP level
- **Health Status**: Distribution of check results
- **Activity Heatmaps**: Coming soon

## 🔐 Security Features

### File Security
- File signature validation
- Content scanning for malicious patterns
- Size and type restrictions
- Secure filename sanitization

### Input Validation
- SQL injection prevention
- XSS protection
- Path traversal prevention
- Input length and format validation

### Audit Logging
- Complete user action tracking
- API request logging
- System event monitoring
- Encrypted sensitive details

### Rate Limiting
- Per-user rate limiting
- Global request throttling
- Configurable limits
- Automatic cooldown periods

## 🛠️ Development

### Adding New Indicator Types

1. Update `INDICATOR_TYPES` in `config.py`
2. Add normalization logic in `IndicatorNormalizer`
3. Add classification patterns in `IndicatorClassifier`
4. Update health checking logic if needed

### Adding New Health Check Sources

1. Create new checker class in `health_checker.py`
2. Implement check methods
3. Update `HealthCheckManager` to use new checker
4. Add configuration for new service

### Custom Security Rules

Update validation patterns in `utils.py`:
- Add new malicious patterns to `SecurityValidator`
- Customize file type restrictions
- Add new encryption algorithms

## 📝 Sample Data

The project includes `sample_iocs.csv` with example indicators:
- Malicious IPs
- Suspicious domains
- Defanged URLs
- File hashes
- Email addresses

## 🚨 Security Considerations

### Production Deployment
- Change default `SECRET_KEY`
- Use proper authentication system (JWT with real validation)
- Configure HTTPS/TLS
- Set up proper database with access controls
- Enable all security features
- Regular security updates

### Access Control
- Implement proper user management
- Use strong authentication methods
- Configure role-based access appropriately
- Monitor audit logs regularly

### Data Protection
- Enable encryption for sensitive data
- Configure appropriate data retention
- Regular backups
- Secure key management

## 🐛 Troubleshooting

### Common Issues

**Database Connection Error:**
- Check `DATABASE_URL` configuration
- Ensure database file permissions
- Verify SQLite installation

**File Upload Failing:**
- Check file size limits
- Verify file type is allowed
- Ensure upload directory exists and is writable

**Health Checks Not Working:**
- Check internet connectivity
- Verify DNS resolution
- Check rate limiting settings

**High Memory Usage:**
- Reduce batch processing size
- Check data retention settings
- Monitor log file sizes

### Logging

Logs are written to:
- `cti_application.log` - Application logs
- `audit.log` - Audit trail
- Console output for immediate feedback

Set `LOG_LEVEL=DEBUG` for detailed troubleshooting.

## 📜 License

This project is provided as-is for educational and demonstration purposes. Ensure compliance with your organization's security policies and legal requirements before production use.

## 🤝 Contributing

This is a demonstration project. For production use:
1. Implement proper authentication
2. Add comprehensive test coverage
3. Set up CI/CD pipelines
4. Add monitoring and alerting
5. Implement proper error handling
6. Add internationalization support

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review configuration settings
3. Check log files for errors
4. Verify all dependencies are installed correctly

---

## 🎯 Quick Start Example

1. **Start via interactive launcher (recommended):**
```powershell
.\.venv\Scripts\Activate.ps1
python start.py    # choose GUI, API, or Both
```

2. **Alternatively, start both services directly:**
```powershell
python launcher.py both --gui-port 8501 --api-port 8000
```

3. **Upload the sample file:**
   - Go to "File Upload" in the GUI
   - Upload `sample_iocs.csv`
   - Enable health checks
   - Click "Process Files"

4. **View results:**
   - Check the Dashboard for statistics
   - Browse indicators in "Indicator Management"
   - Monitor health checks in "Health Checks"
   - View processing logs in "Audit Logs"

5. **Use the API:**

**PowerShell:**
```powershell
# Get indicators
curl -Uri 'http://localhost:8000/api/v1/indicators' -Headers @{'Authorization'='Bearer demo-token'}

# Get statistics
curl -Uri 'http://localhost:8000/api/v1/statistics' -Headers @{'Authorization'='Bearer demo-token'}
```

**Unix/Linux/Mac:**
```bash
# Get indicators
curl -H "Authorization: Bearer demo-token" \
     http://localhost:8000/api/v1/indicators

# Get statistics
curl -H "Authorization: Bearer demo-token" \
     http://localhost:8000/api/v1/statistics
```

The platform is now ready for cyber threat intelligence operations! 🛡️

---

## 🔧 Troubleshooting (Environment)

### "python-multipart" required for file uploads
- Symptom: FastAPI error mentioning `python-multipart` when hitting `/api/v1/indicators/upload`.
- Fix: Ensure you’re using the local virtual environment and it has the package installed.
  ```powershell
  .\.venv\Scripts\Activate.ps1
  python -c "import sys; print(sys.executable)"   # should print .venv path
  python -m pip show python-multipart             # should be installed
  ```

### UnicodeEncodeError on Windows console
- Symptom: `UnicodeEncodeError` for emoji characters when running the launcher.
- Fix: run with UTF‑8 or use the interactive menu:
  ```powershell
  python -X utf8 launcher.py both
  # or
  python start.py
  ```
