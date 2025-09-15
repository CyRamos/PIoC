# 🛠️ PIoC Development Guide

This guide is for developers who want to contribute to or modify the PIoC platform.

## 🔧 Development Setup

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/CyRamos/PIoC
cd PIoC

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt
```

### 2. Dependency Management

We use **pip-tools** for deterministic dependency management:

```bash
# Install pip-tools
pip install pip-tools

# Add new dependency to requirements.in or requirements-dev.in
# Then compile:
pip-compile requirements.in
pip-compile requirements-dev.in

# Install updated dependencies
pip install -r requirements-dev.txt
```

### 3. Project Structure

```
PIoC/
├── requirements.in          # High-level dependencies
├── requirements.txt         # Locked dependencies (auto-generated)
├── requirements-dev.in      # Development dependencies
├── requirements-dev.txt     # Locked dev dependencies (auto-generated)
├── api_server.py           # FastAPI backend
├── gui_app.py              # Streamlit frontend
├── launcher.py             # Application launcher
├── config.py               # Configuration management
├── models.py               # Database models
├── indicator_processor.py   # Core indicator processing
├── health_checker.py       # Health checking logic
├── utils.py                # Utility functions
├── auth.py                 # Authentication
└── exports/                # Export directory
```

## 📦 Dependency Management Explained

### Why pip-tools?

1. **Deterministic builds**: Exact versions for reproducible environments
2. **Separation of concerns**: High-level deps vs. locked deps
3. **Conflict resolution**: Automatically resolves version conflicts
4. **Production-ready**: Widely used in enterprise environments

### Workflow

```bash
# 1. Edit requirements.in to add/remove/update dependencies
vim requirements.in

# 2. Compile to generate locked requirements.txt
pip-compile requirements.in

# 3. Install the new requirements
pip install -r requirements.txt

# 4. For development dependencies:
vim requirements-dev.in
pip-compile requirements-dev.in
pip install -r requirements-dev.txt
```

### Files Explanation

- **requirements.in**: High-level dependencies with flexible versions
- **requirements.txt**: Automatically generated with exact versions
- **requirements-dev.in**: Development-only dependencies
- **requirements-dev.txt**: Locked development dependencies

## 🧪 Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=.

# Run specific test file
pytest tests/test_indicators.py

# Run async tests
pytest -v tests/test_health_checker.py
```

## 🔍 Code Quality

```bash
# Lint and format code
ruff check .
ruff format .

# Type checking (if mypy is added)
mypy .
```

## 🔄 Common Development Tasks

### Adding a New Dependency

```bash
# 1. Add to requirements.in
echo "new-package>=1.0.0" >> requirements.in

# 2. Compile
pip-compile requirements.in

# 3. Install
pip install -r requirements.txt
```

### Updating Dependencies

```bash
# Update all dependencies to latest compatible versions
pip-compile --upgrade requirements.in
pip-compile --upgrade requirements-dev.in

# Install updates
pip install -r requirements-dev.txt
```

### Creating a Release

```bash
# 1. Ensure all dependencies are up to date
pip-compile requirements.in
pip-compile requirements-dev.in

# 2. Test everything works
pytest
python launcher.py  # Quick smoke test

# 3. Commit the locked files
git add requirements.txt requirements-dev.txt
git commit -m "Update locked dependencies for release"

# 4. Tag the release
git tag v1.0.0
git push origin v1.0.0
```

## 🏗️ Architecture

### Core Components

1. **FastAPI Backend** (`api_server.py`):
   - REST API endpoints
   - Authentication & rate limiting
   - Background task processing

2. **Streamlit Frontend** (`gui_app.py`):
   - Web-based user interface
   - File upload & visualization
   - Interactive dashboards

3. **Indicator Processing** (`indicator_processor.py`):
   - IOC normalization
   - Deduplication logic
   - File format support

4. **Health Checking** (`health_checker.py`):
   - Async health validation
   - Multiple reputation sources
   - Concurrent processing

### Database Models

- **Indicator**: Core IOC storage
- **HealthCheck**: Validation results
- **AuditLog**: Security audit trail

## 🔐 Security Considerations

1. **Input Validation**: All inputs are sanitized
2. **Rate Limiting**: API endpoints are rate-limited
3. **Authentication**: Bearer token authentication
4. **Audit Logging**: All actions are logged
5. **File Validation**: Uploaded files are validated

## 📋 Development Checklist

Before submitting changes:

- [ ] Code follows project style (ruff)
- [ ] Tests pass (`pytest`)
- [ ] Dependencies are properly locked
- [ ] Documentation is updated
- [ ] Security considerations addressed
- [ ] Manual testing performed

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Update dependencies if needed
5. Run tests and linting
6. Submit a pull request

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [pip-tools Documentation](https://pip-tools.readthedocs.io/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
