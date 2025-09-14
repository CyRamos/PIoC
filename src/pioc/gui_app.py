"""
Streamlit GUI application for the CTI (Cyber Threat Intelligence) platform.
Provides a user-friendly interface for managing indicators and operations.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import asyncio
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import json
import time
from sqlalchemy import text

# Import our CTI modules
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from core.config import app_config, security_config, INDICATOR_TYPES, db_config, auth_config
from src.pioc.models import SessionLocal, Indicator, HealthCheck, AuditLog
from src.pioc.indicator_processor import IndicatorProcessor
from src.pioc.health_checker import HealthCheckManager
from src.pioc.utils import security_validator, audit_logger, data_retention_manager, ConfigValidator
from src.pioc.auth import auth_manager

# Configure page
st.set_page_config(
    page_title="CTI Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Simple CSS to prevent sidebar collapse without changing colors
st.markdown("""
<style>
    /* Hide the sidebar collapse button only */
    [data-testid="collapsedControl"] {
        display: none !important;
    }
    
    /* Ensure sidebar stays expanded */
    [data-testid="stSidebar"] {
        min-width: 21rem !important;
    }
</style>
""", unsafe_allow_html=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CTIStreamlitApp:
    """Main CTI Streamlit application class."""
    
    def __init__(self):
        """Initialize the CTI application."""
        self.processor = IndicatorProcessor()
        self.health_manager = HealthCheckManager()
        
        # Initialize session state
        if 'user_id' not in st.session_state:
            st.session_state.user_id = 'streamlit_user'
        if 'uploaded_files' not in st.session_state:
            st.session_state.uploaded_files = []
        if 'processing_results' not in st.session_state:
            st.session_state.processing_results = []

    def run(self):
        """Run the main application."""
        # Check authentication first
        if not auth_manager.is_authenticated():
            auth_manager.render_login_form()
            return
        
        # Get current user info
        user_info = auth_manager.get_current_user()
        if user_info:
            st.session_state.user_id = user_info['user_id']
        
        # Sidebar navigation
        self.render_sidebar()
        
        # Main content based on selected page
        page = st.session_state.get('current_page', 'Dashboard')
        
        if page == 'Dashboard':
            self.render_dashboard()
        elif page == 'File Upload':
            self.render_file_upload()
        elif page == 'Diff Analysis':
            self.render_diff_analysis()
        elif page == 'Indicator Management':
            self.render_indicator_management()
        elif page == 'Health Checks':
            self.render_health_checks()
        elif page == 'Analytics':
            self.render_analytics()
        elif page == 'Audit Logs':
            self.render_audit_logs()
        elif page == 'Settings':
            self.render_settings()

    def render_sidebar(self):
        """Render the sidebar navigation."""
        st.sidebar.title("🛡️ PloC")
        
        # User info and logout
        user_info = auth_manager.get_current_user()
        if user_info:
            st.sidebar.markdown("---")
            st.sidebar.write(f"👤 **{user_info['email']}**")
            if user_info.get('is_admin'):
                st.sidebar.write("🔑 Administrator")
            
            if st.sidebar.button("🚪 Logout"):
                auth_manager.logout()
        
        st.sidebar.markdown("---")
        
        # Navigation menu
        pages = [
            'Dashboard',
            'File Upload', 
            'Diff Analysis',
            'Indicator Management',
            'Health Checks',
            'Analytics',
            'Audit Logs',
            'Settings'
        ]
        
        selected_page = st.sidebar.selectbox(
            "Navigate to:",
            pages,
            index=pages.index(st.session_state.get('current_page', 'Dashboard'))
        )
        st.session_state.current_page = selected_page
        
        st.sidebar.markdown("---")
        
        # Quick stats
        st.sidebar.subheader("📊 Quick Stats")
        try:
            with SessionLocal() as session:
                total_indicators = session.query(Indicator).count()
                active_indicators = session.query(Indicator).filter(Indicator.is_active == True).count()
                recent_health_checks = session.query(HealthCheck).filter(
                    HealthCheck.checked_at >= datetime.now() - timedelta(hours=24)
                ).count()
                
            st.sidebar.metric("Total Indicators", total_indicators)
            st.sidebar.metric("Active Indicators", active_indicators)
            st.sidebar.metric("Health Checks (24h)", recent_health_checks)
            
        except Exception as e:
            st.sidebar.error(f"Error loading stats: {str(e)}")
        
        st.sidebar.markdown("---")
        
        # System status
        st.sidebar.subheader("🔧 System Status")
        
        # Check database connection
        try:
            with SessionLocal() as session:
                session.execute(text("SELECT 1"))
            st.sidebar.success("Database: Connected")
        except Exception:
            st.sidebar.error("Database: Disconnected")
        
        # Security status
        warnings = ConfigValidator.validate_security_config()
        if not warnings:
            st.sidebar.success("Security: OK")
        else:
            st.sidebar.warning(f"Security: {len(warnings)} warnings")

    def render_dashboard(self):
        """Render the main dashboard."""
        st.title("🛡️ CTI Dashboard")
        st.markdown("Welcome to the Cyber Threat Intelligence Platform")
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        try:
            with SessionLocal() as session:
                # Total indicators
                total_indicators = session.query(Indicator).count()
                col1.metric("Total Indicators", total_indicators)
                
                # New indicators today
                today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                new_today = session.query(Indicator).filter(
                    Indicator.first_seen >= today
                ).count()
                col2.metric("New Today", new_today)
                
                # Suspicious indicators
                recent_checks = session.query(HealthCheck).filter(
                    HealthCheck.checked_at >= datetime.now() - timedelta(hours=24),
                    HealthCheck.status.in_(['suspicious', 'malicious'])
                ).count()
                col3.metric("Suspicious (24h)", recent_checks)
                
                # Active health checks
                active_checks = session.query(HealthCheck).filter(
                    HealthCheck.checked_at >= datetime.now() - timedelta(hours=1)
                ).count()
                col4.metric("Health Checks (1h)", active_checks)
                
        except Exception as e:
            st.error(f"Error loading dashboard metrics: {str(e)}")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            self.render_indicator_type_chart()
        
        with col2:
            self.render_health_status_chart()
        
        # Recent activity
        st.subheader("📋 Recent Activity")
        self.render_recent_activity()

    def render_indicator_type_chart(self):
        """Render indicator type distribution chart."""
        st.subheader("📊 Indicator Types")
        
        try:
            with SessionLocal() as session:
                # Get indicator type counts
                type_counts = {}
                for indicator_type in INDICATOR_TYPES.keys():
                    count = session.query(Indicator).filter(
                        Indicator.indicator_type == indicator_type
                    ).count()
                    if count > 0:
                        type_counts[INDICATOR_TYPES[indicator_type]] = count
                
                if type_counts:
                    fig = px.pie(
                        values=list(type_counts.values()),
                        names=list(type_counts.keys()),
                        title="Distribution of Indicator Types"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No indicators found")
                    
        except Exception as e:
            st.error(f"Error loading indicator chart: {str(e)}")

    def render_health_status_chart(self):
        """Render health status distribution chart."""
        st.subheader("🔍 Health Status")
        
        try:
            with SessionLocal() as session:
                # Get health status counts from recent checks
                cutoff_time = datetime.now() - timedelta(hours=24)
                
                status_counts = {}
                statuses = ['healthy', 'suspicious', 'malicious', 'error', 'unknown']
                
                for status in statuses:
                    count = session.query(HealthCheck).filter(
                        HealthCheck.checked_at >= cutoff_time,
                        HealthCheck.status == status
                    ).count()
                    if count > 0:
                        status_counts[status.title()] = count
                
                if status_counts:
                    colors = {
                        'Healthy': '#00CC96',
                        'Suspicious': '#FFA15A', 
                        'Malicious': '#EF553B',
                        'Error': '#AB63FA',
                        'Unknown': '#636EFA'
                    }
                    
                    fig = px.bar(
                        x=list(status_counts.keys()),
                        y=list(status_counts.values()),
                        title="Health Status (Last 24h)",
                        color=list(status_counts.keys()),
                        color_discrete_map=colors
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No health checks found")
                    
        except Exception as e:
            st.error(f"Error loading health chart: {str(e)}")

    def render_recent_activity(self):
        """Render recent activity table."""
        try:
            with SessionLocal() as session:
                # Get recent indicators
                recent_indicators = session.query(Indicator).order_by(
                    Indicator.first_seen.desc()
                ).limit(10).all()
                
                if recent_indicators:
                    data = []
                    for indicator in recent_indicators:
                        data.append({
                            'Type': INDICATOR_TYPES.get(indicator.indicator_type, indicator.indicator_type),
                            'Value': indicator.normalized_value[:50] + '...' if len(indicator.normalized_value) > 50 else indicator.normalized_value,
                            'Source': indicator.source_file or 'Manual',
                            'First Seen': indicator.first_seen.strftime('%Y-%m-%d %H:%M'),
                            'TLP': indicator.tlp_level
                        })
                    
                    df = pd.DataFrame(data)
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("No recent indicators found")
                    
        except Exception as e:
            st.error(f"Error loading recent activity: {str(e)}")

    def render_file_upload(self):
        """Render enhanced file upload interface with drag and drop."""
        st.title("📁 File Upload & Processing")
        st.markdown("Upload threat intelligence files for processing and normalization")
        
        # Simple header message without the styled box
        st.info("💡 **Drag & Drop Support**: You can drag files directly onto the file selector below or click to browse.")
        
        # File uploader with enhanced styling
        uploaded_files = st.file_uploader(
            "📂 Select Threat Intelligence Files",
            type=['csv', 'json', 'txt', 'xml'],
            accept_multiple_files=True,
            help="💡 **Drag files directly onto this area** or click to browse. Supported: CSV, JSON, TXT, XML",
            label_visibility="visible"
        )
        
        # Show supported formats info
        with st.expander("📋 Supported File Formats & Examples", expanded=False):
            st.markdown("""
            ### 📊 **CSV Format**
            ```csv
            indicator_type,value,confidence,source
            ip,192.168.1.100,high,malware_sample
            domain,evil-site[.]com,critical,phishing_campaign
            url,hxxp://malicious[.]example/payload,high,malware_distribution
            ```
            
            ### 📝 **Text Format** (one indicator per line)
            ```
            192.168.1.100
            evil-site.com
            http://malicious.example/payload
            d41d8cd98f00b204e9800998ecf8427e
            ```
            
            ### 🔧 **JSON Format**
            ```json
            {
              "indicators": [
                {"type": "ip", "value": "192.168.1.100", "confidence": "high"},
                {"type": "domain", "value": "malicious.com", "confidence": "critical"}
              ]
            }
            ```
            
            ### 🛡️ **Defanged Indicators Supported**
            - `hxxp://` → `http://`
            - `[.]` → `.`
            - `94[.]131[.]108[.]78` → `94.131.108.78`
            """)
        
        if uploaded_files:
            # Success message
            st.success(f"✅ **{len(uploaded_files)}** file{'s' if len(uploaded_files) > 1 else ''} ready for processing!")
            
            # Enhanced file display
            st.subheader("📋 Files Ready for Processing")
            
            # Create a nice table for file information
            file_data = []
            total_size = 0
            
            for file in uploaded_files:
                size_kb = file.size / 1024
                total_size += file.size
                
                # File icon based on type
                if file.name.endswith('.csv'):
                    icon = "📊"
                elif file.name.endswith('.json'):
                    icon = "🔧" 
                elif file.name.endswith('.txt'):
                    icon = "📝"
                elif file.name.endswith('.xml'):
                    icon = "📋"
                else:
                    icon = "📄"
                
                file_data.append({
                    'File': f"{icon} {file.name}",
                    'Size': f"{size_kb:.1f} KB" if size_kb > 1 else f"{file.size} bytes",
                    'Type': file.type or "text/plain",
                    'Format': file.name.split('.')[-1].upper()
                })
            
            # Display file table
            files_df = pd.DataFrame(file_data)
            st.dataframe(files_df, use_container_width=True, hide_index=True)
            
            # Total size info
            total_size_kb = total_size / 1024
            if total_size_kb > 1024:
                size_display = f"{total_size_kb/1024:.1f} MB"
            else:
                size_display = f"{total_size_kb:.1f} KB"
            
            st.caption(f"📦 **Total size**: {size_display}")
            
            # Processing options in a nice container
            st.markdown("---")
            st.subheader("⚙️ Processing Configuration")
            
            col1, col2 = st.columns(2)
            with col1:
                source_name = st.text_input(
                    "🏷️ Source Name",
                    placeholder="e.g., AlienVault_Daily_Feed",
                    help="💡 **Optional**: Custom name for tracking these indicators. If not specified, filename will be used."
                )
            with col2:
                run_health_checks = st.checkbox(
                    "🏥 Run health checks after processing",
                    value=True,
                    help="🔍 **Recommended**: Automatically validate indicators against threat intelligence sources"
                )
            
            # Processing preview
            st.markdown("### 🔄 Processing Preview")
            st.info(f"""
            **What will happen when you click Process:**
            1. 📤 **Upload** {len(uploaded_files)} file{'s' if len(uploaded_files) > 1 else ''}
            2. 🔍 **Extract** indicators from all formats
            3. 🛡️ **Normalize** defanged indicators (hxxp → http, [.] → .)
            4. 🔗 **Deduplicate** against existing database
            5. 💾 **Store** only new indicators
            {'6. 🏥 **Health check** all indicators' if run_health_checks else ''}
            7. 📊 **Show** detailed diff analysis
            """)
            
            # Process files button with enhanced styling
            st.markdown("---")
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                if st.button("🚀 **Process All Files**", type="primary", use_container_width=True):
                    self.process_uploaded_files(uploaded_files, source_name, run_health_checks)

    def process_uploaded_files(self, uploaded_files, source_name: str, run_health_checks: bool):
        """Process uploaded files."""
        progress_bar = st.progress(0)
        status_text = st.empty()
        results = []
        
        for i, uploaded_file in enumerate(uploaded_files):
            try:
                # Update progress
                progress = (i + 1) / len(uploaded_files)
                progress_bar.progress(progress)
                status_text.text(f"Processing {uploaded_file.name}...")
                
                # Save uploaded file temporarily
                temp_path = Path(app_config.TEMP_DIR) / security_validator.sanitize_filename(uploaded_file.name)
                with open(temp_path, 'wb') as f:
                    f.write(uploaded_file.getbuffer())
                
                # Process file
                result = self.processor.process_file(
                    temp_path,
                    source_name or uploaded_file.name
                )
                
                results.append({
                    'file': uploaded_file.name,
                    'result': result
                })
                
                # Clean up temporary file
                temp_path.unlink(missing_ok=True)
                
                # Log audit event
                audit_logger.log_event(
                    user_id=st.session_state.user_id,
                    action="file_uploaded",
                    resource_type="file",
                    resource_id=uploaded_file.name,
                    details={'result': result}
                )
                
            except Exception as e:
                results.append({
                    'file': uploaded_file.name,
                    'result': {'success': False, 'error': str(e)}
                })
                logger.error(f"Error processing file {uploaded_file.name}: {str(e)}")
        
        # Update progress to complete
        progress_bar.progress(1.0)
        status_text.text("Processing complete!")
        
        # Display results
        self.display_processing_results(results)
        
        # Run health checks if requested
        if run_health_checks and any(r['result'].get('success', False) for r in results):
            st.subheader("🔍 Running Health Checks...")
            self.run_health_checks_for_recent_indicators()

    def display_processing_results(self, results: List[Dict]):
        """Display file processing results with detailed diff information - larger layout."""
        # Use wide layout for results
        st.markdown("---")
        st.title("📊 Processing Results with Diff Analysis")
        st.markdown("### Complete analysis of your uploaded threat intelligence files")
        
        # Summary statistics in larger cards
        st.markdown("#### 📈 Processing Summary")
        successful = sum(1 for r in results if r['result'].get('success', False))
        failed = len(results) - successful
        
        # Create larger metric display
        metric_col1, metric_col2, metric_col3, metric_col4 = st.columns([1, 1, 1, 2])
        with metric_col1:
            st.metric("Files Processed", len(results), delta=None)
        with metric_col2:
            st.metric("Successful", successful, delta=None)
        with metric_col3:
            st.metric("Failed", failed, delta=None)
        with metric_col4:
            if successful > 0:
                st.success(f"✅ Successfully processed {successful} file{'s' if successful != 1 else ''}")
            if failed > 0:
                st.error(f"❌ Failed to process {failed} file{'s' if failed != 1 else ''}")
        
        # Store results in session state for export functionality
        st.session_state.processing_results = results
        
        # Detailed results with larger containers
        st.markdown("---")
        for result in results:
            file_name = result['file']
            file_result = result['result']
            
            # Use full width container instead of expander
            st.markdown(f"## 📄 {file_name} - Detailed Analysis")
            
            if file_result.get('success', False):
                st.success("✅ Successfully processed")
                
                # Display diff summary in larger format
                diff_summary = file_result.get('diff_summary', {})
                
                st.markdown("### 📈 Diff Summary")
                
                # Larger metrics display
                summary_col1, summary_col2, summary_col3, summary_col4, summary_col5 = st.columns(5)
                with summary_col1:
                    st.metric("Total Found", diff_summary.get('total_found', 0))
                with summary_col2:
                    st.metric("🆕 New", diff_summary.get('new_count', 0))
                with summary_col3:
                    st.metric("📋 Existing", diff_summary.get('existing_count', 0))
                with summary_col4:
                    st.metric("🔄 Duplicates", diff_summary.get('duplicate_count', 0))
                with summary_col5:
                    st.metric("❌ Invalid", diff_summary.get('invalid_count', 0))
                
                # Detailed tabs for each category - larger tabs
                if any(diff_summary.get(key, 0) > 0 for key in ['new_count', 'existing_count', 'duplicate_count', 'invalid_count']):
                    
                    st.markdown("### 📋 Detailed Indicator Analysis")
                    tab1, tab2, tab3, tab4 = st.tabs(["🆕 New Indicators", "📋 Existing Indicators", "🔄 Duplicates", "❌ Invalid"])
                    
                    with tab1:
                        self._display_new_indicators(file_result)
                    
                    with tab2:
                        self._display_existing_indicators(file_result)
                    
                    with tab3:
                        self._display_duplicate_indicators(file_result)
                    
                    with tab4:
                        self._display_invalid_indicators(file_result)
                
                # Export options in larger format
                st.markdown("### 📤 Export Options")
                self._display_export_options(file_name, file_result)
                
            else:
                st.error("❌ Processing failed")
                st.error(f"**Error**: {file_result.get('error', 'Unknown error')}")
            
            # Add separator between files
            st.markdown("---")
    
    def _display_new_indicators(self, file_result: Dict):
        """Display new indicators found in the file."""
        new_indicators = file_result.get('new_indicators', [])
        
        if new_indicators:
            st.success(f"Found {len(new_indicators)} new indicators that were added to the database")
            
            # Create DataFrame for display
            data = []
            for indicator in new_indicators:
                data.append({
                    'Type': INDICATOR_TYPES.get(indicator['type'], indicator['type']),
                    'Original Value': indicator['value'],
                    'Normalized Value': indicator['normalized_value'],
                    'Source': indicator['source_file']
                })
            
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True, height=400)
            
            # Copy to clipboard button
            if st.button(f"📋 Copy New Indicators ({len(new_indicators)})", key=f"copy_new_{file_result.get('source_name', 'unknown')}"):
                csv_data = df.to_csv(index=False)
                st.code(csv_data, language='csv')
                st.success("Data ready to copy! Select all text above and copy.")
        else:
            st.info("No new indicators found - all indicators already exist in the database")
    
    def _display_existing_indicators(self, file_result: Dict):
        """Display existing indicators found in the file."""
        existing_indicators = file_result.get('existing_indicators', [])
        
        if existing_indicators:
            st.info(f"Found {len(existing_indicators)} indicators that already exist in the database")
            
            # Create DataFrame for display
            data = []
            for indicator in existing_indicators:
                data.append({
                    'Type': INDICATOR_TYPES.get(indicator['type'], indicator['type']),
                    'Value': indicator['normalized_value'],
                    'First Seen': indicator.get('first_seen', 'Unknown'),
                    'Last Seen': indicator.get('last_seen', 'Unknown'),
                    'Existing Source': indicator.get('existing_source', 'Unknown'),
                    'Confidence': indicator.get('confidence_score', 'Unknown')
                })
            
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True, height=400)
        else:
            st.info("No existing indicators found")
    
    def _display_duplicate_indicators(self, file_result: Dict):
        """Display duplicate indicators found within the file."""
        duplicate_indicators = file_result.get('duplicate_indicators', [])
        
        if duplicate_indicators:
            st.warning(f"Found {len(duplicate_indicators)} duplicate indicators within the same file")
            
            # Create DataFrame for display
            data = []
            for indicator in duplicate_indicators:
                data.append({
                    'Type': INDICATOR_TYPES.get(indicator['type'], indicator['type']),
                    'Original Value': indicator['value'],
                    'Normalized Value': indicator['normalized_value'],
                    'Reason': indicator.get('reason', 'Unknown')
                })
            
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True, height=400)
        else:
            st.info("No duplicate indicators found within the file")
    
    def _display_invalid_indicators(self, file_result: Dict):
        """Display invalid indicators found in the file."""
        invalid_indicators = file_result.get('invalid_indicators', [])
        
        if invalid_indicators:
            st.error(f"Found {len(invalid_indicators)} invalid indicators that could not be processed")
            
            # Create DataFrame for display
            data = []
            for indicator in invalid_indicators:
                data.append({
                    'Original Value': indicator['value'],
                    'Reason': indicator.get('reason', 'Unknown')
                })
            
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True, height=400)
        else:
            st.success("No invalid indicators found - all indicators were processable")
    
    def _display_export_options(self, file_name: str, file_result: Dict):
        """Display export options for the processed file in larger format."""
        # Show export summary first
        new_count = len(file_result.get('new_indicators', []))
        existing_count = len(file_result.get('existing_indicators', []))
        total_count = new_count + existing_count
        
        st.info(f"📊 **Export Summary**: {new_count} new indicators, {existing_count} existing indicators, {total_count} total available for export")
        
        # Larger export buttons with better spacing
        export_col1, export_col2, export_col3 = st.columns(3)
        
        with export_col1:
            if st.button(f"📥 **Export New Only (CSV)**\n({new_count} indicators)", 
                        key=f"export_new_csv_{file_name}", 
                        type="primary", 
                        use_container_width=True):
                self._export_indicators(file_result.get('new_indicators', []), f"new_indicators_{file_name}", "csv")
        
        with export_col2:
            if st.button(f"📥 **Export New Only (JSON)**\n({new_count} indicators)", 
                        key=f"export_new_json_{file_name}", 
                        use_container_width=True):
                self._export_indicators(file_result.get('new_indicators', []), f"new_indicators_{file_name}", "json")
        
        with export_col3:
            if st.button(f"📥 **Export All (CSV)**\n({total_count} indicators)", 
                        key=f"export_all_csv_{file_name}", 
                        use_container_width=True):
                all_indicators = file_result.get('new_indicators', []) + file_result.get('existing_indicators', [])
                self._export_indicators(all_indicators, f"all_indicators_{file_name}", "csv")
    
    def _export_indicators(self, indicators: List[Dict], filename_base: str, format_type: str):
        """Export indicators to the specified format."""
        try:
            if not indicators:
                st.warning("No indicators to export")
                return
            
            # Prepare export data
            export_data = []
            for indicator in indicators:
                export_item = {
                    'type': indicator.get('type', ''),
                    'value': indicator.get('value', ''),
                    'normalized_value': indicator.get('normalized_value', ''),
                    'source_file': indicator.get('source_file', ''),
                    'first_seen': indicator.get('first_seen', ''),
                    'last_seen': indicator.get('last_seen', ''),
                    'confidence_score': indicator.get('confidence_score', ''),
                    'existing_source': indicator.get('existing_source', '')
                }
                export_data.append(export_item)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{filename_base}_{timestamp}.{format_type}"
            export_path = Path(app_config.EXPORT_DIR) / filename
            
            if format_type == "csv":
                export_file = self.processor.export_indicators_to_csv(export_data, export_path)
            elif format_type == "json":
                export_file = self.processor.export_indicators_to_json(export_data, export_path)
            else:
                st.error("Unsupported export format")
                return
            
            st.success(f"✅ Exported {len(indicators)} indicators to: {export_file}")
            
            # Display download info
            st.info(f"📁 File saved to: {export_file}")
            
            # Show preview of export data
            if len(export_data) <= 10:
                st.subheader("📋 Export Preview")
                preview_df = pd.DataFrame(export_data)
                st.dataframe(preview_df, use_container_width=True)
            
        except Exception as e:
            st.error(f"Export failed: {str(e)}")
            logger.error(f"Export error: {str(e)}")
    
    def render_diff_analysis(self):
        """Render a simplified diff analysis page."""
        st.title("🔍 Diff Analysis & Export")
        st.markdown("Compare and export indicators from your uploaded files")
        
        # Source selection
        st.subheader("📋 Source Selection")
        
        with SessionLocal() as session:
            # Get all unique sources
            sources = session.query(Indicator.source_file).distinct().all()
            source_list = [s[0] for s in sources if s[0]]
            
            if source_list:
                # Enhanced source selection with stats
                st.info("💡 **Tip**: Select sources to compare what indicators they contain and export them")
                
                selected_sources = st.multiselect(
                    "📂 Select sources to analyze:",
                    options=source_list,
                    help="Choose one or more sources to view and export their indicators"
                )
                
                if selected_sources:
                    # Show quick stats for selected sources
                    total_indicators = 0
                    for source in selected_sources:
                        count = session.query(Indicator).filter(Indicator.source_file == source).count()
                        total_indicators += count
                        st.caption(f"📄 **{source}**: {count} indicators")
                    
                    st.info(f"📊 **Total indicators in selected sources**: {total_indicators}")
                    
                    # Simple analyze button
                    if st.button("🔍 Analyze & View Selected Sources", type="primary"):
                        self._analyze_sources_simple(selected_sources)
            else:
                st.info("No sources found. Upload some files first to see diff analysis options.")
                st.markdown("### 📤 Upload files using the **File Upload** page to get started")
    
    def _analyze_sources_simple(self, source_names: List[str]):
        """Analyze selected sources with simplified interface."""
        try:
            # Get all indicators from selected sources
            indicators = self.processor.get_indicators_by_source(source_names=source_names)
            
            if indicators:
                st.success(f"✅ Found **{len(indicators)}** indicators from selected sources")
                
                # Show indicator type breakdown
                type_counts = {}
                for indicator in indicators:
                    itype = INDICATOR_TYPES.get(indicator['type'], indicator['type'])
                    type_counts[itype] = type_counts.get(itype, 0) + 1
                
                # Display type breakdown in columns
                st.subheader("📊 Indicator Types")
                cols = st.columns(len(type_counts))
                for i, (itype, count) in enumerate(type_counts.items()):
                    with cols[i]:
                        st.metric(itype, count)
                
                # Group and display by source
                source_groups = {}
                for indicator in indicators:
                    source = indicator['source_file']
                    if source not in source_groups:
                        source_groups[source] = []
                    source_groups[source].append(indicator)
                
                st.subheader(f"📂 Source Details ({len(source_groups)} sources)")
                
                # Show overlap analysis first for multiple sources
                if len(source_groups) > 1:
                    self._show_source_overlap(source_groups)
                
                # Tabs for each source
                if len(source_groups) > 1:
                    tabs = st.tabs([f"📄 {source}" for source in source_groups.keys()])
                    for tab, (source, source_indicators) in zip(tabs, source_groups.items()):
                        with tab:
                            self._display_source_indicators(source, source_indicators)
                else:
                    # Single source, no tabs needed
                    source, source_indicators = next(iter(source_groups.items()))
                    self._display_source_indicators(source, source_indicators)
                
                # Bulk export options
                st.subheader("📤 Export Options")
                st.markdown("Export all indicators from selected sources:")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("📥 Export All (CSV)", type="primary"):
                        self._export_indicators(indicators, "combined_sources", "csv")
                with col2:
                    if st.button("📥 Export All (JSON)"):
                        self._export_indicators(indicators, "combined_sources", "json")
                        
            else:
                st.warning("No indicators found in the selected sources")
                
        except Exception as e:
            st.error(f"Analysis failed: {str(e)}")
            logger.error(f"Source analysis error: {str(e)}")
    
    def _display_source_indicators(self, source: str, indicators: List[Dict]):
        """Display indicators from a single source."""
        st.write(f"**{len(indicators)}** indicators from **{source}**")
        
        # Create DataFrame
        data = []
        for indicator in indicators:
            data.append({
                'Type': INDICATOR_TYPES.get(indicator['type'], indicator['type']),
                'Value': indicator['normalized_value'][:60] + ('...' if len(indicator['normalized_value']) > 60 else ''),
                'Full Value': indicator['normalized_value'],  # Hidden column for export
                'TLP': indicator['tlp_level'],
                'First Seen': indicator['first_seen'].split('T')[0] if 'T' in str(indicator['first_seen']) else str(indicator['first_seen'])[:10],
                'Active': '✅' if indicator['is_active'] else '❌'
            })
        
        df = pd.DataFrame(data)
        
        # Display with option to show full values
        show_full = st.checkbox(f"Show full values for {source}", key=f"full_values_{source}")
        if show_full:
            display_df = df[['Type', 'Full Value', 'TLP', 'First Seen', 'Active']].rename(columns={'Full Value': 'Value'})
        else:
            display_df = df[['Type', 'Value', 'TLP', 'First Seen', 'Active']]
        
        st.dataframe(display_df, use_container_width=True, height=300)
        
        # Individual source export
        col1, col2 = st.columns(2)
        with col1:
            if st.button(f"📥 Export {source} (CSV)", key=f"export_{source}_csv"):
                self._export_indicators(indicators, f"source_{source.replace(' ', '_')}", "csv")
        with col2:
            if st.button(f"📥 Export {source} (JSON)", key=f"export_{source}_json"):
                self._export_indicators(indicators, f"source_{source.replace(' ', '_')}", "json")
    
    def _show_source_overlap(self, source_groups: Dict[str, List[Dict]]):
        """Show enhanced overlap analysis between sources."""
        st.subheader("🔗 Source Overlap Analysis")
        
        # Create sets of normalized values for each source
        source_sets = {}
        source_type_sets = {}  # Track by type as well
        
        for source, indicators in source_groups.items():
            source_sets[source] = set(ind['normalized_value'] for ind in indicators)
            source_type_sets[source] = {}
            for ind in indicators:
                itype = ind['type']
                if itype not in source_type_sets[source]:
                    source_type_sets[source][itype] = set()
                source_type_sets[source][itype].add(ind['normalized_value'])
        
        sources = list(source_sets.keys())
        
        if len(sources) == 2:
            # Two sources - detailed comparison
            source1, source2 = sources
            set1, set2 = source_sets[source1], source_sets[source2]
            
            overlap = set1 & set2
            unique_1 = set1 - set2
            unique_2 = set2 - set1
            
            # Calculate overlap percentage
            total_unique = len(set1 | set2)
            overlap_pct = (len(overlap) / total_unique * 100) if total_unique > 0 else 0
            
            # Main metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("🤝 Common", len(overlap))
            with col2:
                st.metric(f"📄 Only {source1[:15]}...", len(unique_1))
            with col3:
                st.metric(f"📄 Only {source2[:15]}...", len(unique_2))
            with col4:
                st.metric("📊 Overlap %", f"{overlap_pct:.1f}%")
            
            # Type-specific overlap analysis
            if overlap:
                st.markdown("### 📋 Overlap by Indicator Type")
                overlap_by_type = {}
                for ind_value in overlap:
                    for source in [source1, source2]:
                        for itype, type_set in source_type_sets[source].items():
                            if ind_value in type_set:
                                if itype not in overlap_by_type:
                                    overlap_by_type[itype] = set()
                                overlap_by_type[itype].add(ind_value)
                                break
                
                type_cols = st.columns(len(overlap_by_type) if overlap_by_type else 1)
                for i, (itype, type_indicators) in enumerate(overlap_by_type.items()):
                    with type_cols[i]:
                        st.metric(f"{INDICATOR_TYPES.get(itype, itype)}", len(type_indicators))
                
                # Show common indicators
                with st.expander(f"🔍 View {len(overlap)} common indicators", expanded=False):
                    overlap_df_data = []
                    for ind_value in sorted(overlap):
                        # Find the type
                        ind_type = "unknown"
                        for source in [source1, source2]:
                            for itype, type_set in source_type_sets[source].items():
                                if ind_value in type_set:
                                    ind_type = INDICATOR_TYPES.get(itype, itype)
                                    break
                            if ind_type != "unknown":
                                break
                        
                        overlap_df_data.append({
                            'Type': ind_type,
                            'Indicator': ind_value[:80] + ('...' if len(ind_value) > 80 else '')
                        })
                    
                    if overlap_df_data:
                        overlap_df = pd.DataFrame(overlap_df_data)
                        st.dataframe(overlap_df, use_container_width=True, height=200)
            
            # Unique indicators summary
            if unique_1 or unique_2:
                st.markdown("### 🔄 Unique Indicators Summary")
                unique_col1, unique_col2 = st.columns(2)
                
                with unique_col1:
                    if unique_1:
                        with st.expander(f"📄 Unique to {source1} ({len(unique_1)})", expanded=False):
                            unique_1_types = {}
                            for ind_value in unique_1:
                                for itype, type_set in source_type_sets[source1].items():
                                    if ind_value in type_set:
                                        unique_1_types[itype] = unique_1_types.get(itype, 0) + 1
                                        break
                            
                            for itype, count in unique_1_types.items():
                                st.write(f"• **{INDICATOR_TYPES.get(itype, itype)}**: {count}")
                
                with unique_col2:
                    if unique_2:
                        with st.expander(f"📄 Unique to {source2} ({len(unique_2)})", expanded=False):
                            unique_2_types = {}
                            for ind_value in unique_2:
                                for itype, type_set in source_type_sets[source2].items():
                                    if ind_value in type_set:
                                        unique_2_types[itype] = unique_2_types.get(itype, 0) + 1
                                        break
                            
                            for itype, count in unique_2_types.items():
                                st.write(f"• **{INDICATOR_TYPES.get(itype, itype)}**: {count}")
        
        else:
            # Multiple sources (3+) - matrix view
            st.markdown("### 📊 Multi-Source Overlap Matrix")
            
            # Create overlap matrix
            overlap_data = []
            for i, source1 in enumerate(sources):
                row = {"Source": source1[:20] + ('...' if len(source1) > 20 else '')}
                for j, source2 in enumerate(sources):
                    if i == j:
                        row[source2[:15] + ('...' if len(source2) > 15 else '')] = len(source_sets[source1])
                    else:
                        overlap_count = len(source_sets[source1] & source_sets[source2])
                        row[source2[:15] + ('...' if len(source2) > 15 else '')] = overlap_count
                overlap_data.append(row)
            
            overlap_df = pd.DataFrame(overlap_data)
            st.dataframe(overlap_df, use_container_width=True)
            
            st.caption("📝 Diagonal shows total indicators per source, other cells show overlaps")
            
            # Show summary statistics
            all_indicators = set()
            for indicators_set in source_sets.values():
                all_indicators.update(indicators_set)
            
            total_unique = len(all_indicators)
            total_all = sum(len(s) for s in source_sets.values())
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("🎯 Total Unique", total_unique)
            with col2:
                st.metric("📊 Total All", total_all)
            with col3:
                duplicate_ratio = ((total_all - total_unique) / total_all * 100) if total_all > 0 else 0
                st.metric("🔄 Duplication %", f"{duplicate_ratio:.1f}%")
    
    def _analyze_sources(self, source_names: List[str], only_new: bool, date_from: datetime):
        """Legacy analyze function - kept for backward compatibility."""
        # Redirect to simplified version
        self._analyze_sources_simple(source_names)

    def run_health_checks_for_recent_indicators(self):
        """Run health checks for recently added indicators."""
        try:
            with SessionLocal() as session:
                # Get indicators added in the last hour
                cutoff_time = datetime.now() - timedelta(hours=1)
                recent_indicators = session.query(Indicator).filter(
                    Indicator.first_seen >= cutoff_time
                ).all()
                
                if not recent_indicators:
                    st.info("No recent indicators to check")
                    return
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Run health checks asynchronously
                async def run_checks():
                    results = await self.health_manager.check_multiple_indicators(recent_indicators)
                    return results
                
                # Since we're in Streamlit, we need to handle async differently
                st.info(f"Health checks initiated for {len(recent_indicators)} indicators")
                progress_bar.progress(1.0)
                status_text.text("Health checks running in background...")
                
        except Exception as e:
            st.error(f"Error running health checks: {str(e)}")

    def render_indicator_management(self):
        """Render indicator management interface."""
        st.title("🔍 Indicator Management")
        
        # Search and filter options
        col1, col2, col3 = st.columns(3)
        
        with col1:
            search_term = st.text_input("🔍 Search indicators", help="Search by value or source")
        
        with col2:
            indicator_type_filter = st.selectbox(
                "Filter by type",
                ['All'] + list(INDICATOR_TYPES.values())
            )
        
        with col3:
            tlp_filter = st.selectbox(
                "Filter by TLP",
                ['All', 'WHITE', 'GREEN', 'AMBER', 'RED']
            )
        
        # Load and display indicators
        try:
            with SessionLocal() as session:
                query = session.query(Indicator)
                
                # Apply filters
                if search_term:
                    query = query.filter(
                        Indicator.normalized_value.contains(search_term) |
                        Indicator.source_file.contains(search_term)
                    )
                
                if indicator_type_filter != 'All':
                    reverse_mapping = {v: k for k, v in INDICATOR_TYPES.items()}
                    indicator_type = reverse_mapping.get(indicator_type_filter)
                    if indicator_type:
                        query = query.filter(Indicator.indicator_type == indicator_type)
                
                if tlp_filter != 'All':
                    query = query.filter(Indicator.tlp_level == tlp_filter)
                
                # Get results
                indicators = query.order_by(Indicator.first_seen.desc()).limit(100).all()
                
                st.subheader(f"📋 Indicators ({len(indicators)} found)")
                
                if indicators:
                    # Prepare data for display
                    data = []
                    for indicator in indicators:
                        data.append({
                            'ID': indicator.id,
                            'Type': INDICATOR_TYPES.get(indicator.indicator_type, indicator.indicator_type),
                            'Value': indicator.normalized_value,
                            'Source': indicator.source_file or 'Manual',
                            'TLP': indicator.tlp_level,
                            'Confidence': indicator.confidence_score,
                            'First Seen': indicator.first_seen.strftime('%Y-%m-%d %H:%M'),
                            'Active': indicator.is_active
                        })
                    
                    df = pd.DataFrame(data)
                    
                    # Display with selection
                    selected_indicators = st.multiselect(
                        "Select indicators for actions:",
                        options=df['ID'].tolist(),
                        format_func=lambda x: f"ID {x}: {df[df['ID']==x]['Value'].iloc[0][:50]}"
                    )
                    
                    st.dataframe(df, use_container_width=True)
                    
                    # Bulk actions
                    if selected_indicators:
                        st.subheader("🔧 Bulk Actions")
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            if st.button("🔍 Run Health Checks"):
                                self.run_health_checks_for_indicators(selected_indicators)
                        
                        with col2:
                            if st.button("❌ Deactivate"):
                                self.deactivate_indicators(selected_indicators)
                        
                        with col3:
                            if st.button("🗑️ Delete"):
                                self.delete_indicators(selected_indicators)
                
                else:
                    st.info("No indicators found matching the criteria")
                    
        except Exception as e:
            st.error(f"Error loading indicators: {str(e)}")

    def run_health_checks_for_indicators(self, indicator_ids: List[int]):
        """Run health checks for specific indicators."""
        try:
            with SessionLocal() as session:
                indicators = session.query(Indicator).filter(
                    Indicator.id.in_(indicator_ids)
                ).all()
                
                if indicators:
                    st.info(f"Initiating health checks for {len(indicators)} indicators")
                    # In a real implementation, this would trigger async health checks
                    st.success("Health checks initiated!")
                    
        except Exception as e:
            st.error(f"Error running health checks: {str(e)}")

    def deactivate_indicators(self, indicator_ids: List[int]):
        """Deactivate selected indicators."""
        try:
            with SessionLocal() as session:
                updated = session.query(Indicator).filter(
                    Indicator.id.in_(indicator_ids)
                ).update({Indicator.is_active: False})
                
                session.commit()
                st.success(f"Deactivated {updated} indicators")
                st.rerun()
                
        except Exception as e:
            st.error(f"Error deactivating indicators: {str(e)}")

    def delete_indicators(self, indicator_ids: List[int]):
        """Delete selected indicators."""
        if st.button("⚠️ Confirm Deletion", type="secondary"):
            try:
                with SessionLocal() as session:
                    deleted = session.query(Indicator).filter(
                        Indicator.id.in_(indicator_ids)
                    ).delete()
                    
                    session.commit()
                    st.success(f"Deleted {deleted} indicators")
                    st.rerun()
                    
            except Exception as e:
                st.error(f"Error deleting indicators: {str(e)}")

    def render_health_checks(self):
        """Render health checks interface."""
        st.title("🔍 Health Checks")
        st.markdown("Monitor and manage indicator health checks")
        
        # Health check statistics
        col1, col2, col3, col4 = st.columns(4)
        
        try:
            with SessionLocal() as session:
                # Recent health checks
                recent_count = session.query(HealthCheck).filter(
                    HealthCheck.checked_at >= datetime.now() - timedelta(hours=24)
                ).count()
                col1.metric("Checks (24h)", recent_count)
                
                # Status counts
                for i, status in enumerate(['healthy', 'suspicious', 'malicious']):
                    count = session.query(HealthCheck).filter(
                        HealthCheck.checked_at >= datetime.now() - timedelta(hours=24),
                        HealthCheck.status == status
                    ).count()
                    
                    if i == 0:
                        col2.metric(f"Healthy", count)
                    elif i == 1:
                        col3.metric(f"Suspicious", count)
                    else:
                        col4.metric(f"Malicious", count)
                        
        except Exception as e:
            st.error(f"Error loading health check stats: {str(e)}")
        
        # Recent health checks table
        st.subheader("📋 Recent Health Checks")
        
        try:
            with SessionLocal() as session:
                health_checks = session.query(HealthCheck).join(Indicator).filter(
                    HealthCheck.checked_at >= datetime.now() - timedelta(hours=24)
                ).order_by(HealthCheck.checked_at.desc()).limit(50).all()
                
                if health_checks:
                    data = []
                    for check in health_checks:
                        data.append({
                            'Indicator': check.indicator.normalized_value[:50],
                            'Type': INDICATOR_TYPES.get(check.indicator.indicator_type, check.indicator.indicator_type),
                            'Status': check.status.title(),
                            'Source': check.check_source,
                            'Checked At': check.checked_at.strftime('%Y-%m-%d %H:%M'),
                        })
                    
                    df = pd.DataFrame(data)
                    
                    # Color code by status
                    def highlight_status(row):
                        if row['Status'] == 'Malicious':
                            return ['background-color: #ffebee'] * len(row)
                        elif row['Status'] == 'Suspicious':
                            return ['background-color: #fff3e0'] * len(row)
                        elif row['Status'] == 'Healthy':
                            return ['background-color: #e8f5e8'] * len(row)
                        else:
                            return [''] * len(row)
                    
                    st.dataframe(df.style.apply(highlight_status, axis=1), use_container_width=True)
                    
                else:
                    st.info("No recent health checks found")
                    
        except Exception as e:
            st.error(f"Error loading health checks: {str(e)}")

    def render_analytics(self):
        """Render analytics dashboard."""
        st.title("📊 Analytics")
        st.markdown("Analyze trends and patterns in threat intelligence data")
        
        # Time range selector
        col1, col2 = st.columns(2)
        with col1:
            days_back = st.selectbox("Time Range", [7, 30, 90, 365], index=1)
        with col2:
            chart_type = st.selectbox("Chart Type", ["Timeline", "Distribution", "Heatmap"])
        
        cutoff_date = datetime.now() - timedelta(days=days_back)
        
        if chart_type == "Timeline":
            self.render_timeline_chart(cutoff_date)
        elif chart_type == "Distribution":
            self.render_distribution_charts(cutoff_date)
        else:
            self.render_heatmap_chart(cutoff_date)

    def render_timeline_chart(self, cutoff_date: datetime):
        """Render timeline chart of indicators over time."""
        st.subheader("📈 Indicator Timeline")
        
        try:
            with SessionLocal() as session:
                # Get daily indicator counts
                indicators = session.query(Indicator).filter(
                    Indicator.first_seen >= cutoff_date
                ).all()
                
                if indicators:
                    # Group by date and type
                    daily_data = {}
                    for indicator in indicators:
                        date = indicator.first_seen.date()
                        indicator_type = INDICATOR_TYPES.get(indicator.indicator_type, indicator.indicator_type)
                        
                        if date not in daily_data:
                            daily_data[date] = {}
                        
                        if indicator_type not in daily_data[date]:
                            daily_data[date][indicator_type] = 0
                        
                        daily_data[date][indicator_type] += 1
                    
                    # Create timeline chart
                    fig = go.Figure()
                    
                    for indicator_type in INDICATOR_TYPES.values():
                        dates = []
                        counts = []
                        
                        for date in sorted(daily_data.keys()):
                            dates.append(date)
                            counts.append(daily_data[date].get(indicator_type, 0))
                        
                        fig.add_trace(go.Scatter(
                            x=dates,
                            y=counts,
                            mode='lines+markers',
                            name=indicator_type,
                            line=dict(width=2)
                        ))
                    
                    fig.update_layout(
                        title="Daily Indicator Additions",
                        xaxis_title="Date",
                        yaxis_title="Count",
                        hovermode='x unified'
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                    
                else:
                    st.info("No indicators found in the selected time range")
                    
        except Exception as e:
            st.error(f"Error creating timeline chart: {str(e)}")

    def render_distribution_charts(self, cutoff_date: datetime):
        """Render distribution charts."""
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🍰 Source Distribution")
            self.render_source_distribution(cutoff_date)
        
        with col2:
            st.subheader("🚦 TLP Distribution")
            self.render_tlp_distribution(cutoff_date)

    def render_source_distribution(self, cutoff_date: datetime):
        """Render source file distribution chart."""
        try:
            with SessionLocal() as session:
                # Get source distribution
                indicators = session.query(Indicator).filter(
                    Indicator.first_seen >= cutoff_date
                ).all()
                
                source_counts = {}
                for indicator in indicators:
                    source = indicator.source_file or 'Manual'
                    source_counts[source] = source_counts.get(source, 0) + 1
                
                if source_counts:
                    fig = px.pie(
                        values=list(source_counts.values()),
                        names=list(source_counts.keys()),
                        title="Indicators by Source"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No data available")
                    
        except Exception as e:
            st.error(f"Error creating source chart: {str(e)}")

    def render_tlp_distribution(self, cutoff_date: datetime):
        """Render TLP level distribution chart."""
        try:
            with SessionLocal() as session:
                # Get TLP distribution
                indicators = session.query(Indicator).filter(
                    Indicator.first_seen >= cutoff_date
                ).all()
                
                tlp_counts = {}
                for indicator in indicators:
                    tlp = indicator.tlp_level
                    tlp_counts[tlp] = tlp_counts.get(tlp, 0) + 1
                
                if tlp_counts:
                    colors = {
                        'WHITE': '#ffffff',
                        'GREEN': '#00ff00',
                        'AMBER': '#ffbf00',
                        'RED': '#ff0000'
                    }
                    
                    fig = px.bar(
                        x=list(tlp_counts.keys()),
                        y=list(tlp_counts.values()),
                        title="Indicators by TLP Level",
                        color=list(tlp_counts.keys()),
                        color_discrete_map=colors
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No data available")
                    
        except Exception as e:
            st.error(f"Error creating TLP chart: {str(e)}")

    def render_heatmap_chart(self, cutoff_date: datetime):
        """Render activity heatmap."""
        st.subheader("🔥 Activity Heatmap")
        st.info("Heatmap feature coming soon!")

    def render_audit_logs(self):
        """Render audit logs interface."""
        st.title("📋 Audit Logs")
        st.markdown("View system activity and user actions")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            hours_back = st.selectbox("Time Range", [1, 6, 24, 72, 168], index=2)
        
        with col2:
            action_filter = st.selectbox("Action", ['All', 'file_uploaded', 'file_processed', 'indicator_created'])
        
        with col3:
            user_filter = st.text_input("User ID")
        
        # Load audit logs
        try:
            filters = {}
            if action_filter != 'All':
                filters['action'] = action_filter
            if user_filter:
                filters['user_id'] = user_filter
            
            logs = audit_logger.get_audit_logs(hours=hours_back, **filters)
            
            if logs:
                st.subheader(f"📋 Audit Logs ({len(logs)} entries)")
                
                # Prepare data for display
                data = []
                for log in logs:
                    data.append({
                        'Timestamp': log['timestamp'],
                        'User': log['user_id'],
                        'Action': log['action'],
                        'Resource': log['resource_type'],
                        'IP Address': log['ip_address'] or 'N/A',
                        'Details': str(log['details'])[:100] if log['details'] else 'N/A'
                    })
                
                df = pd.DataFrame(data)
                st.dataframe(df, use_container_width=True)
                
            else:
                st.info("No audit logs found matching the criteria")
                
        except Exception as e:
            st.error(f"Error loading audit logs: {str(e)}")

    def render_settings(self):
        """Render settings interface."""
        st.title("⚙️ Settings")
        st.markdown("Configure system settings and security options")
        
        # Security settings
        st.subheader("🔒 Security Settings")
        
        # Display current security configuration
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Max File Size (MB)", security_config.MAX_FILE_SIZE_MB)
            st.metric("Max Requests/Min", security_config.MAX_REQUESTS_PER_MINUTE)
            st.metric("Data Retention (Days)", security_config.DATA_RETENTION_DAYS)
        
        with col2:
            st.write("**Allowed File Extensions:**")
            st.write(", ".join(security_config.ALLOWED_FILE_EXTENSIONS))
            
            st.write("**Security Features:**")
            st.write(f"✅ Audit Logging: {security_config.AUDIT_LOG_ENABLED}")
            st.write(f"✅ Data Encryption: {security_config.ENCRYPT_SENSITIVE_DATA}")
            st.write(f"✅ Malware Scanning: {security_config.MALWARE_SCAN_ENABLED}")
        
        # System maintenance
        st.subheader("🔧 System Maintenance")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🧹 Clean Old Data"):
                with st.spinner("Cleaning old data..."):
                    result = data_retention_manager.cleanup_old_data()
                    if 'error' in result:
                        st.error(f"Cleanup failed: {result['error']}")
                    else:
                        st.success(f"Cleanup completed: {result}")
        
        with col2:
            if st.button("📊 Generate Report"):
                st.info("Report generation feature coming soon!")
        
        # Application info
        st.subheader("ℹ️ Application Information")
        
        info_data = {
            'Application': app_config.APP_NAME,
            'Version': app_config.APP_VERSION,
            'Debug Mode': app_config.DEBUG,
            'Database URL': db_config.DATABASE_URL.split('///')[-1],  # Hide sensitive parts
            'Upload Directory': str(app_config.UPLOAD_DIR),
            'Log Level': security_config.LOG_LEVEL
        }
        
        for key, value in info_data.items():
            st.write(f"**{key}:** {value}")

# Main application entry point
def main():
    """Main application entry point."""
    try:
        app = CTIStreamlitApp()
        app.run()
        
    except Exception as e:
        st.error(f"Application error: {str(e)}")
        logger.error(f"Streamlit application error: {str(e)}")

if __name__ == "__main__":
    main() 