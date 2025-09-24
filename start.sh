#!/bin/bash
# Start script for PIoC Platform on Render

echo "🚀 Starting PIoC Platform..."

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
export CTI_REQUIRE_AUTH="true"
export CTI_DEBUG="false"
export CTI_LOG_LEVEL="INFO"
export RENDER_DEPLOYMENT="true"

# Install dependencies
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements/requirements.txt

# Start the application
echo "🌐 Starting Streamlit GUI..."
python -m streamlit run src/pioc/gui_app.py \
    --server.port $PORT \
    --server.address 0.0.0.0 \
    --server.headless true \
    --browser.gatherUsageStats false
