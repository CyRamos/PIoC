"""
Authentication module for the CTI platform.
Handles user authentication, session management, and integration with cyterous.com.
"""

import streamlit as st
import requests
import re
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import logging

from config import auth_config, security_config
from utils import audit_logger

logger = logging.getLogger(__name__)

class AuthManager:
    """Manages authentication and user sessions."""
    
    def __init__(self):
        """Initialize authentication manager."""
        self.session_key = "cti_auth_session"
        self.user_key = "cti_user_info"
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        if not auth_config.REQUIRE_AUTH:
            return True
        
        session_data = st.session_state.get(self.session_key)
        if not session_data:
            return False
        
        # Check session expiry
        if datetime.now() > session_data.get('expires_at', datetime.now()):
            self.logout()
            return False
        
        return True
    
    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get current user information."""
        if not self.is_authenticated():
            return None
        
        return st.session_state.get(self.user_key)
    
    def login_with_email(self, email: str) -> bool:
        """
        Authenticate user with email.
        
        Args:
            email: User email address
            
        Returns:
            True if authentication successful
        """
        try:
            # Validate email format
            if not self._is_valid_email(email):
                st.error("Invalid email format")
                return False
            
            # Check if email domain is allowed
            if not self._is_domain_allowed(email):
                st.error("Email domain not allowed")
                return False
            
            # Verify with cyterous.com if API is configured
            if auth_config.CYTEROUS_API_KEY and auth_config.CYTEROUS_API_URL:
                if not self._verify_with_cyterous(email):
                    st.error("Email verification failed")
                    return False
            
            # Create user session
            user_info = {
                'email': email,
                'is_admin': email in auth_config.ADMIN_EMAILS,
                'login_time': datetime.now(),
                'user_id': self._generate_user_id(email)
            }
            
            session_data = {
                'authenticated': True,
                'expires_at': datetime.now() + timedelta(minutes=auth_config.SESSION_TIMEOUT_MINUTES),
                'user_id': user_info['user_id']
            }
            
            # Store in session state
            st.session_state[self.session_key] = session_data
            st.session_state[self.user_key] = user_info
            st.session_state['user_id'] = user_info['user_id']
            
            # Log authentication event
            audit_logger.log_event(
                user_id=user_info['user_id'],
                action="user_login",
                resource_type="auth",
                details={'email': email, 'method': 'email'}
            )
            
            logger.info(f"User authenticated: {email}")
            return True
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            st.error("Authentication failed")
            return False
    
    def logout(self):
        """Logout current user."""
        user_info = self.get_current_user()
        if user_info:
            # Log logout event
            audit_logger.log_event(
                user_id=user_info['user_id'],
                action="user_logout",
                resource_type="auth",
                details={'email': user_info['email']}
            )
        
        # Clear session state
        if self.session_key in st.session_state:
            del st.session_state[self.session_key]
        if self.user_key in st.session_state:
            del st.session_state[self.user_key]
        if 'user_id' in st.session_state:
            del st.session_state['user_id']
        
        st.rerun()
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _is_domain_allowed(self, email: str) -> bool:
        """Check if email domain is allowed."""
        if not auth_config.ALLOWED_DOMAINS:
            return True
        
        domain = email.split('@')[1].lower()
        return domain in [d.lower() for d in auth_config.ALLOWED_DOMAINS]
    
    def _verify_with_cyterous(self, email: str) -> bool:
        """
        Verify email with cyterous.com API.
        
        Args:
            email: Email to verify
            
        Returns:
            True if verification successful
        """
        try:
            url = f"{auth_config.CYTEROUS_API_URL}{auth_config.CYTEROUS_AUTH_ENDPOINT}"
            headers = {
                'Authorization': f'Bearer {auth_config.CYTEROUS_API_KEY}',
                'Content-Type': 'application/json'
            }
            data = {'email': email}
            
            response = requests.post(url, json=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                return result.get('verified', False)
            else:
                logger.warning(f"Cyterous verification failed: {response.status_code}")
                # Allow login even if verification service is down
                return True
                
        except Exception as e:
            logger.error(f"Error verifying with cyterous.com: {str(e)}")
            # Allow login even if verification service is down
            return True
    
    def _generate_user_id(self, email: str) -> str:
        """Generate a unique user ID from email."""
        return hashlib.sha256(email.encode()).hexdigest()[:16]
    
    def render_login_form(self):
        """Render the login form."""
        st.title("✨ Pretty IoC")
        st.markdown("**PloC Login** - Please authenticate to access the Platform")
        
        # Integration notice
        if auth_config.CYTEROUS_API_KEY:
            st.info("🔗 Integrated with cyterous.com authentication")
        
        with st.form("login_form"):
            st.subheader("Email Authentication")
            
            email = st.text_input(
                "Email Address",
                placeholder="your.email@cyterous.com",
                help="Enter your email address to authenticate"
            )
            
            remember_me = st.checkbox(
                "Remember me for 30 days",
                help="Keep you logged in for extended period"
            )
            
            submitted = st.form_submit_button("🔐 Login", type="primary")
            
            if submitted and email:
                if self.login_with_email(email):
                    st.success("✅ Authentication successful!")
                    st.rerun()
        
        # Additional information
        st.markdown("---")
        st.subheader("ℹ️ Authentication Information")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Allowed Domains:**")
            for domain in auth_config.ALLOWED_DOMAINS:
                st.write(f"• {domain}")
        
        with col2:
            st.write("**Features:**")
            st.write("• Secure email-based authentication")
            st.write("• Integration with cyterous.com")
            st.write("• Session management")
            st.write("• Audit logging")
        
        # Contact information
        st.markdown("---")
        st.info("💬 Need access? Contact your administrator or visit [cyterous.com](https://cyterous.com)")

class AuthDecorator:
    """Decorator for protecting Streamlit pages."""
    
    def __init__(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager
    
    def require_auth(self, func):
        """Decorator to require authentication for a function."""
        def wrapper(*args, **kwargs):
            if not self.auth_manager.is_authenticated():
                self.auth_manager.render_login_form()
                return None
            return func(*args, **kwargs)
        return wrapper

# Global authentication manager
auth_manager = AuthManager()
auth_decorator = AuthDecorator(auth_manager) 