# 🐍 Python Version Compatibility Guide

## Summary

**PIoC supports Python 3.7+ only. Python 2.7 is NOT supported.**

## 🚫 Why Python 2.7 Won't Work

### 1. Core Dependencies Require Python 3.6+
- **FastAPI**: Minimum Python 3.6+ (uses async/await, type hints)
- **Streamlit**: Minimum Python 3.7+
- **Pydantic v2**: Minimum Python 3.7+
- **Modern asyncio**: Requires Python 3.7+

### 2. Modern Python Features Used
Your application extensively uses Python 3+ only features:
- **Async/await syntax**: Found in 4 files (63 occurrences)
- **Type hints**: Throughout the codebase
- **f-strings**: Modern string formatting
- **pathlib.Path**: Modern file operations
- **dataclasses**: Python 3.7+ feature

### 3. Python 2.7 End of Life
- Reached end-of-life: **January 1, 2020**
- No security updates
- Modern libraries dropped support

## ✅ Supported Python Versions

| Python Version | Support Level | Docker Image | Notes |
|---------------|---------------|--------------|-------|
| **3.11** | ✅ Recommended | `Dockerfile` | Full feature support, latest libraries |
| **3.10** | ✅ Supported | `Dockerfile` | Full feature support |
| **3.9** | ✅ Supported | `Dockerfile` | Full feature support |
| **3.8** | ✅ Supported | `Dockerfile` | Full feature support |
| **3.7** | ⚠️ Legacy | `Dockerfile.python37` | Minimum viable, older library versions |
| **3.6** | ❌ Not supported | - | Some dependencies require 3.7+ |
| **2.7** | ❌ Not supported | - | Incompatible |

## 🐳 Docker Multi-Version Setup

### Option 1: Latest Python (Recommended)
```bash
# Use the main Dockerfile (Python 3.11)
docker-compose up -d
```

### Option 2: Legacy Python 3.7
```bash
# Use the Python 3.7 compatible version
docker-compose --profile python37 -f docker-compose.multi-python.yml up -d
```

Access points for Python 3.7 version:
- **GUI**: http://localhost:8502
- **API**: http://localhost:8001

## 🔧 Local Installation by Python Version

### Python 3.11 (Recommended)
```bash
pip install -r requirements/requirements.txt
python run.py --both
```

### Python 3.7 (Legacy)
```bash
pip install -r requirements/requirements-python37.txt
python run.py --both
```

## 📦 Library Version Differences

### Python 3.11 (Latest)
- FastAPI 0.104.1
- Streamlit 1.28.2
- Pydantic v2.5.1
- Pandas 2.1.4

### Python 3.7 (Legacy)
- FastAPI 0.68.2
- Streamlit 1.12.2
- Pydantic v1.10.12
- Pandas 1.3.5

## 🚨 Migration from Python 2.7

If you need Python 2.7 support, you would need to:

### Complete Rewrite Required
1. **Replace FastAPI** → Flask/Django
2. **Replace Streamlit** → Custom web interface
3. **Replace modern async** → Threading/multiprocessing
4. **Replace type hints** → Manual documentation
5. **Replace f-strings** → .format() or % formatting
6. **Replace pathlib** → os.path
7. **Downgrade all dependencies** to 2.7-compatible versions

### Estimated Effort
- **Time**: 2-4 weeks full rewrite
- **Complexity**: High - fundamental architecture changes
- **Maintenance**: Ongoing security/compatibility issues

## 🎯 Recommendations

1. **Use Python 3.11+** for new deployments
2. **Use Python 3.7 Docker image** for legacy environments
3. **Do NOT attempt Python 2.7 port** - create new simple tool instead
4. **Upgrade legacy systems** to Python 3.7+ if possible

## 🔍 Checking Your Python Version

```bash
# Check your Python version
python --version

# Check if specific version is available
python3.11 --version
python3.7 --version

# In Python shell
import sys
print(sys.version_info)
```

## 📞 Support

For Python version issues:
1. Check this compatibility guide
2. Use appropriate Docker image
3. Verify your Python installation
4. Check dependency compatibility
