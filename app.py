from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, g, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from contextlib import contextmanager
import os
import pandas as pd
import io
import logging
from logging.handlers import RotatingFileHandler
import shutil
from datetime import datetime
import secrets
import string
from sqlalchemy import distinct, func, or_, extract
import importlib
from typing import TYPE_CHECKING

# Try a runtime import of python-magic (module name: magic). If unavailable, fall back gracefully.
# Using importlib avoids static import errors in environments where the package isn't installed.
try:
    magic_spec = importlib.util.find_spec('magic')
except Exception:
    magic_spec = None

if magic_spec is not None:
    try:
        magic = importlib.import_module('magic')
    except Exception:
        magic = None
else:
    # Try common alternative package name as a fallback
    try:
        magic = importlib.import_module('filemagic')
    except Exception:
        magic = None

import sys
import flask
from num2words import num2words
import requests


from dotenv import load_dotenv
load_dotenv()
# ... other imports ...
# ==================== Configuration ====================
# In app.py, update the Config class:
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    
    # Get database URL from environment
    database_url = os.environ.get('DATABASE_URL')
    
    # Fix for SQLAlchemy 1.4+ (Heroku/Supabase compatibility)
    if database_url and database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_DATABASE_URI = database_url or 'sqlite:///revenue_management.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,  # Verify connections before using them
        'pool_recycle': 300,    # Recycle connections after 5 minutes
        'pool_size': 10,        # Connection pool size
        'max_overflow': 20      # Max overflow connections
    }
    
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 16MB
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'png', 'jpg', 'jpeg', 'pdf'}
    ITEMS_PER_PAGE = 20
    
# ==================== OTP Configuration ====================
# SMS Provider Selection
SMS_PROVIDER = os.getenv('SMS_PROVIDER', 'mock').lower()  # mock, twilio, africastalking, vonage

# Legacy compatibility
USE_MOCK_SMS = SMS_PROVIDER == 'mock'

# OTP Settings
MOCK_SMS_LOG_FILE = 'otp_logs.txt'
OTP_EXPIRY_MINUTES = int(os.getenv('OTP_EXPIRY_MINUTES', '5'))

# Twilio Configuration
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')

# Africa's Talking Configuration
AFRICASTALKING_USERNAME = os.getenv('AFRICASTALKING_USERNAME', 'sandbox')
AFRICASTALKING_API_KEY = os.getenv('AFRICASTALKING_API_KEY')

# Vonage Configuration
VONAGE_API_KEY = os.getenv('VONAGE_API_KEY')
VONAGE_API_SECRET = os.getenv('VONAGE_API_SECRET')
VONAGE_SENDER_ID = os.getenv('VONAGE_SENDER_ID', 'AWMA')

# Email Fallback
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
FROM_EMAIL = os.getenv('FROM_EMAIL', SMTP_USERNAME)  

# ==================== App Initialization ====================
app = Flask(__name__)
app.config.from_object(Config)

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('backups', exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# ==================== Request Logging Middleware ====================
@app.before_request
def before_request_logging():
    """Log request details and add request ID"""
    g.request_id = secrets.token_hex(8)
    g.start_time = datetime.now()
    
    # Log request details
    app.logger.info(
        f'Request {g.request_id}: {request.method} {request.path} '
        f'from {request.remote_addr}'
    )

@app.after_request
def after_request_logging(response):
    """Log response details"""
    if hasattr(g, 'start_time'):
        duration = (datetime.now() - g.start_time).total_seconds()
        
        app.logger.info(
            f'Response {g.request_id}: {response.status_code} '
            f'in {duration:.3f}s'
        )
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    """Global exception handler"""
    request_id = getattr(g, 'request_id', 'unknown')
    
    app.logger.error(
        f'Unhandled exception in request {request_id}: {str(e)}',
        exc_info=True
    )
    
    # Don't reveal internal errors to users in production
    if app.debug:
        raise e
    else:
        flash('An unexpected error occurred. Please try again.', 'error')
        return redirect(url_for('index'))

# ==================== Logging Setup ====================
if not app.debug:
    file_handler = RotatingFileHandler('logs/revenue_management.log', maxBytes=10240000, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Revenue Management System startup')

# ==================== Models ====================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False) # <--- New: Required phone number
    is_temp_password = db.Column(db.Boolean, default=True)  # <--- New: Flag for mandatory reset
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # admin, user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    primary_contact = db.Column(db.String(100), nullable=True)
    owner_name = db.Column(db.String(100), nullable=False)
    house_no = db.Column(db.String(50))
    email = db.Column(db.String(120))
    electoral_area = db.Column(db.String(100), nullable=False)
    town = db.Column(db.String(100), nullable=False)
    street_name = db.Column(db.String(100))
    ghanapost_gps = db.Column(db.String(50))
    landmark = db.Column(db.String(200))
    block_no = db.Column(db.String(50), nullable=False)
    parcel_no = db.Column(db.String(50), nullable=False)
    division_no = db.Column(db.String(50), nullable=False)
    account_no = db.Column(db.String(50), unique=True, nullable=False, index=True)
    category = db.Column(db.String(100), nullable=False)
    property_class = db.Column(db.String(50), nullable=False)
    zone = db.Column(db.String(50), nullable=False)
    use_code = db.Column(db.String(50), nullable=False)
    valuation_status = db.Column(db.String(50), nullable=False)
    rateable_value = db.Column(db.Float, nullable=False)
    rate_impost = db.Column(db.Float, nullable=False)
    photo = db.Column(db.String(200))
    supporting_doc1 = db.Column(db.String(200))
    supporting_doc2 = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    invoices = db.relationship('PropertyInvoice', backref='property', lazy=True, cascade='all, delete-orphan')
    
    __table_args__ = (
        db.Index('idx_property_electoral_area', 'electoral_area'),
        db.Index('idx_property_town', 'town'),
    )

class BusinessOccupant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.String(5), unique=True, nullable=False, index=True)  # New: 5-digit ID
    business_name = db.Column(db.String(200), nullable=False)
    business_primary_contact = db.Column(db.String(100), nullable=False)
    business_secondary_contact = db.Column(db.String(100))
    business_website = db.Column(db.String(200))
    business_email = db.Column(db.String(120))
    owner_primary_contact = db.Column(db.String(100), nullable=False)
    owner_name = db.Column(db.String(100), nullable=False)
    house_no = db.Column(db.String(50))
    owner_email = db.Column(db.String(120))
    electoral_area = db.Column(db.String(100), nullable=False)
    town = db.Column(db.String(100), nullable=False)
    street_name = db.Column(db.String(100))
    ghanapost_gps = db.Column(db.String(50))
    landmark = db.Column(db.String(200))
    division_no = db.Column(db.String(50), nullable=False)
    property_account_no = db.Column(db.String(50), nullable=False)
    account_no = db.Column(db.String(50), unique=True, nullable=False, index=True)
    display_category = db.Column(db.String(100), nullable=False)
    category1 = db.Column(db.String(100))
    category2 = db.Column(db.String(100))
    category3 = db.Column(db.String(100))
    category4 = db.Column(db.String(100))
    category5 = db.Column(db.String(100))
    category6 = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    invoices = db.relationship('BOPInvoice', backref='business', lazy=True, cascade='all, delete-orphan')
    
    __table_args__ = (
        db.Index('idx_business_electoral_area', 'electoral_area'),
        db.Index('idx_business_town', 'town'),
    )

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(200), nullable=False)
    category1 = db.Column(db.String(100))
    category2 = db.Column(db.String(100))
    category3 = db.Column(db.String(100))
    category4 = db.Column(db.String(100))
    category5 = db.Column(db.String(100))
    category6 = db.Column(db.String(100))
    amount = db.Column(db.Float, nullable=False)
    rate_impost = db.Column(db.Float, default=0.001350)  #  ADD THIS
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PropertyInvoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_no = db.Column(db.String(50), unique=True, nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))  # ADD THIS
    rateable_value = db.Column(db.Float, nullable=False)
    rate_impost = db.Column(db.Float, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    tax_rate = db.Column(db.Float, default=0.0)  # ADD THIS
    tax_amount = db.Column(db.Float, default=0.0)  # ADD THIS
    total_amount = db.Column(db.Float, nullable=False)  # ADD THIS
    invoice_date = db.Column(db.Date)  # ADD THIS
    due_date = db.Column(db.Date)  # ADD THIS
    description = db.Column(db.Text)  # ADD THIS
    year = db.Column(db.Integer, nullable=False, index=True)
    status = db.Column(db.String(20), default='Unpaid', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payments = db.relationship('Payment', 
                               backref='property_invoice', 
                               lazy=True,
                               foreign_keys='Payment.property_invoice_id')
    adjustments = db.relationship('InvoiceAdjustment', 
                            backref='property_invoice', 
                            lazy=True,
                            foreign_keys='InvoiceAdjustment.property_invoice_id')
class BOPInvoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_no = db.Column(db.String(50), unique=True, nullable=False)
    business_id = db.Column(db.Integer, db.ForeignKey('business_occupant.id'), nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    year = db.Column(db.Integer, nullable=False, index=True)
    status = db.Column(db.String(20), default='Unpaid', index=True)
    invoice_date = db.Column(db.Date)          # <-- added
    due_date = db.Column(db.Date)              # <-- added
    tax_rate = db.Column(db.Float, default=0.0) # <-- added (percentage or decimal per your convention)
    tax_amount = db.Column(db.Float, default=0.0) # <-- optional
    total_amount = db.Column(db.Float, nullable=True) # <-- optional
    description = db.Column(db.Text)           # <-- added
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payments = db.relationship('Payment', 
                               backref='business_invoice', 
                               lazy=True,
                               foreign_keys='Payment.business_invoice_id')
    adjustments = db.relationship('InvoiceAdjustment', 
                            backref='business_invoice', 
                            lazy=True,
                            foreign_keys='InvoiceAdjustment.business_invoice_id')
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_invoice_id = db.Column(db.Integer, db.ForeignKey('property_invoice.id'), nullable=True)
    business_invoice_id = db.Column(db.Integer, db.ForeignKey('bop_invoice.id'), nullable=True)
    invoice_no = db.Column(db.String(50), nullable=False)
    invoice_type = db.Column(db.String(50))
    payment_mode = db.Column(db.String(50), nullable=False)
    payment_type = db.Column(db.String(20), nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    gcr_number = db.Column(db.String(50))
    valuation_number = db.Column(db.String(50))
    paid_by = db.Column(db.String(100), nullable=False)
    payer_name = db.Column(db.String(100))
    payer_phone = db.Column(db.String(20))
    sender_mobile_number = db.Column(db.String(20))
    mobile_transaction_id = db.Column(db.String(100))
    bank_name = db.Column(db.String(100))
    bank_branch = db.Column(db.String(100))
    cheque_name = db.Column(db.String(100))
    cheque_number = db.Column(db.String(50))
    cheque_photo = db.Column(db.String(200))
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Completed')
    created_by = db.Column(db.String(100))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50))
    entity_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='audit_logs', foreign_keys=[user_id])
    
# ==================== OTP Model ====================
# Add this model to your models section
class OTPVerification(db.Model):
    """Store OTP verification codes for payments"""
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(20), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    invoice_id = db.Column(db.Integer, nullable=False)
    invoice_type = db.Column(db.String(20), nullable=False)  # 'Property' or 'Business'
    payment_amount = db.Column(db.Float, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)  # Track verification attempts
    
    def is_valid(self):
        """Check if OTP is still valid"""
        return not self.verified and datetime.utcnow() < self.expires_at and self.attempts < 3
    
    def is_expired(self):
        """Check if OTP has expired"""
        return datetime.utcnow() > self.expires_at   
    
class TemporaryPassword(db.Model):
    """Store temporary passwords for new users"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    temp_password = db.Column(db.String(255), nullable=False)  # Store encrypted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Fix: Explicitly specify foreign keys and disable backrefs that could cause conflicts
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('temp_passwords', lazy='dynamic'))
    creator = db.relationship('User', foreign_keys=[created_by], backref=db.backref('created_temp_passwords', lazy='dynamic'))
    
    def is_valid(self):
        """Check if temporary password is still valid"""
        return not self.used and datetime.utcnow() < self.expires_at
    
    def mark_as_used(self):
        """Mark temporary password as used"""
        self.used = True
        self.used_at = datetime.utcnow()
        db.session.commit() 
    
# Optional: Add this model to app.py if you want to track reset tokens in database
# This provides better security and allows you to invalidate tokens

class PasswordResetToken(db.Model):
    """Track password reset tokens"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime)
    
    user = db.relationship('User', backref='reset_tokens')
    
    def is_valid(self):
        """Check if token is still valid"""
        return not self.used and datetime.utcnow() < self.expires_at
    
    def mark_as_used(self):
        """Mark token as used"""
        self.used = True
        self.used_at = datetime.utcnow()
        db.session.commit()  # Format as 5 digits with leading zeros

# If you use this model, update the forgot_password route:
@app.route('/forgot-password-db', methods=['GET', 'POST'])
def forgot_password_with_db():
    """Forgot password with database token tracking"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email_or_phone = request.form.get('email_or_phone', '').strip()
        
        user = User.query.filter(
            db.or_(
                User.email == email_or_phone,
                User.phone_number == email_or_phone
            )
        ).first()
        
        if user:
            # Invalidate any existing unused tokens
            existing_tokens = PasswordResetToken.query.filter_by(
                user_id=user.id, 
                used=False
            ).all()
            for token in existing_tokens:
                token.used = True
            
            # Generate new token
            token_string = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token_string,
                expires_at=expires_at
            )
            db.session.add(reset_token)
            db.session.commit()
            
            # Create reset link
            reset_link = url_for('reset_password_with_db', token=token_string, _external=True)
            
            log_action('Password reset requested', 'User', user.id)
            app.logger.info(f'Password reset link for {user.username}: {reset_link}')
            
            flash('Password reset instructions have been sent.', 'success')
        else:
            flash('If that contact is registered, you will receive reset instructions.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# And update reset password route:
@app.route('/reset-password-db/<token>', methods=['GET', 'POST'])
def reset_password_with_db(token):
    """Reset password using database-tracked token"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token or not reset_token.is_valid():
        flash('Invalid or expired reset link', 'error')
        return render_template('reset_password.html', token=token, token_valid=False)
    
    user = reset_token.user
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token, token_valid=True)
        
        is_valid, message = validate_password_strength(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template('reset_password.html', token=token, token_valid=True)
        
        user.set_password(new_password)
        user.is_temp_password = False
        reset_token.mark_as_used()
        db.session.commit()
        
        log_action('Password reset completed', 'User', user.id)
        flash('Password reset successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token, token_valid=True)  

# ----------------------------------------------------
# 🔑 FIX 2: Custom Jinja Filter for Currency Conversion
# ----------------------------------------------------
def convert_currency_to_words(amount):
    """
    Converts a float amount into Ghana Cedis and Pesewas in words.
    Ignores 'only' for the Cedis part, adds 'Pesewas only' if fractional.
    """
    try:
        amount = round(float(amount), 2)
        cedis = int(amount)
        pesewas = int(round((amount - cedis) * 100))
        
        # 1. Cedis part
        if cedis > 0:
            cedis_words = num2words(cedis, lang='en')
            result = f"{cedis_words.title()} Ghana Cedis"
        else:
            result = ""

        # 2. Pesewas part
        if pesewas > 0:
            pesewas_words = num2words(pesewas, lang='en')
            # If there were Cedis, add "and", otherwise start the sentence.
            if cedis > 0:
                result += f" and {pesewas_words.title()} Pesewas only"
            else:
                result = f"{pesewas_words.title()} Pesewas only"
        
        # 3. Handle whole numbers without Pesewas
        elif cedis > 0 and pesewas == 0:
             result += " only"

        # Remove extra 'and' from num2words output if present (e.g., in 'one hundred and ten')
        return result.replace(' and ', ' ', 1).strip()
        
    except Exception as e:
        print(f"Error converting number to words: {e}")
        return "AMOUNT IN WORDS ERROR"

# Register the custom filter with Jinja
app.jinja_env.filters['in_words'] = convert_currency_to_words  

# ==================== Utility Functions ====================

# app.py (Around line 240, before utility functions like `transaction_scope`)
def generate_temp_password(length=12):
    """Generate a secure, random temporary password."""
    # Ensure the password has a mix of characters for maximum security
    upper = secrets.choice(string.ascii_uppercase)
    lower = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    symbol = secrets.choice(string.punctuation)
    
    # Generate remaining characters
    all_chars = string.ascii_letters + string.digits + string.punctuation
    remaining_length = length - 4
    remaining = ''.join(secrets.choice(all_chars) for i in range(remaining_length))
    
    # Combine and shuffle to prevent predictable patterns
    temp_password_list = list(upper + lower + digit + symbol + remaining)
    secrets.SystemRandom().shuffle(temp_password_list)
    
    return "".join(temp_password_list)

# ==================== Input Validation Functions ====================
def validate_numeric_input(value, field_name, min_value=0, max_value=None, allow_zero=False):
    """Validate numeric input with range checking"""
    try:
        num = float(value)
        
        if not allow_zero and num == 0:
            raise ValueError(f"{field_name} cannot be zero")
        
        if num < min_value:
            raise ValueError(f"{field_name} must be at least {min_value}")
        
        if max_value is not None and num > max_value:
            raise ValueError(f"{field_name} cannot exceed {max_value}")
        
        return num
    except (ValueError, TypeError) as e:
        if isinstance(e, ValueError) and str(e).startswith(field_name):
            raise e
        raise ValueError(f"Invalid {field_name}: must be a valid number")

def validate_phone_number(phone):
    """Validate Ghana phone number format"""
    import re
    # Remove spaces and dashes
    phone = re.sub(r'[\s\-]', '', phone)
    
    # Check if it matches Ghana phone format (10 digits starting with 0, or with country code)
    pattern = r'^(0|233)\d{9}$'
    if not re.match(pattern, phone):
        raise ValueError("Invalid phone number format. Use format: 0241234567 or 233241234567")
    
    return phone

def validate_email(email):
    """Validate email format"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")
    return email.lower()

def validate_account_number(account_no):
    """Validate account number format"""
    if not account_no or len(account_no.strip()) == 0:
        raise ValueError("Account number is required")
    
    account_no = account_no.strip().upper()
    
    if len(account_no) < 5 or len(account_no) > 20:
        raise ValueError("Account number must be between 5 and 20 characters")
    
    return account_no

def generate_business_id():
    """Generate a 5-digit business ID with leading zeros"""
    last_business = BusinessOccupant.query.order_by(BusinessOccupant.id.desc()).first()
    if last_business:
        next_id = last_business.id + 1
    else:
        next_id = 1
    return f"{next_id:05d}"  # Format as 5 digits with leading zeros

def generate_business_invoice_no(business_id, year):
    """Generate invoice number in format: INVNBOP-{business_id}-{year}"""
    return f"INVNBOP-{business_id}-{year}"

def generate_property_invoice_no(property_id, year):
    """Generate property invoice number in format: INVNBPR-{property.id:05d}-{year}"""
    # property_id is formatted as 5 digits with leading zeros
    formatted_id = f"{property_id:05d}"
    return f"INVNBPR-{formatted_id}-{year}"

# ... existing utility functions ...
@contextmanager
def transaction_scope():
    """Provide a transactional scope for database operations"""
    try:
        yield
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Transaction error: {str(e)}')
        raise e

def allowed_file(filename, allowed_extensions=None):
    """Validate file extensions"""
    if allowed_extensions is None:
        allowed_extensions = app.config['ALLOWED_EXTENSIONS']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def validate_file_upload(file, max_size_mb=1024, allowed_extensions=None):
    """Comprehensive file validation with content verification"""
    if not file or file.filename == '':
        return False, 'No file selected'
    
    if not allowed_file(file.filename, allowed_extensions):
        return False, f'Invalid file type. Allowed: {allowed_extensions}'
    
    # Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > max_size_mb * 1024 * 1024:
        return False, f'File too large. Maximum size: {max_size_mb}MB'
    
    if size == 0:
        return False, 'File is empty'
    
    #  FIX: Verify file content matches extension
    try:
        if magic is None:
            app.logger.warning('python-magic not installed. File content validation skipped.')
            return True, 'Valid'
        
        # Read first 2KB for magic number detection
        file_header = file.read(2048)
        file.seek(0)
        
        mime = magic.from_buffer(file_header, mime=True)
        
        # Define allowed MIME types for each extension
        allowed_mimes = {
            'csv': ['text/csv', 'text/plain', 'application/csv'],
            'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
            'xls': ['application/vnd.ms-excel'],
            'pdf': ['application/pdf'],
            'jpg': ['image/jpeg'],
            'jpeg': ['image/jpeg'],
            'png': ['image/png']
        }
        
        # Get file extension
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        # Verify MIME type matches extension
        if ext in allowed_mimes and mime not in allowed_mimes[ext]:
            return False, f'File content ({mime}) does not match extension (.{ext}). Possible security risk.'
        
    except ImportError:
        # If python-magic is not installed, log warning but continue
        app.logger.warning('python-magic not installed. File content validation skipped.')
    except Exception as e:
        app.logger.error(f'Error during file content validation: {str(e)}')
        return False, f'Error validating file: {str(e)}'
    
    return True, 'Valid'

def log_action(action, entity_type=None, entity_id=None, details=None):
    """Log user actions for audit trail - improved to handle API calls"""
    try:
        user_id = None
        ip_address = None
        
        # Try to get current user if authenticated
        if current_user.is_authenticated:
            user_id = current_user.id
        
        # Try to get IP address from request context
        try:
            ip_address = request.remote_addr
        except RuntimeError:
            # Request context might not be available
            ip_address = 'System'
        
        # Create audit log entry
        audit = AuditLog(
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            ip_address=ip_address
        )
        db.session.add(audit)
        db.session.commit()
        
        # Also log to app logger for debugging
        app.logger.info(f'AUDIT: {action} - User: {user_id}, Entity: {entity_type}/{entity_id}, IP: {ip_address}')
        
    except Exception as e:
        app.logger.error(f'Failed to create audit log: {str(e)}', exc_info=True)
        # Don't raise the exception - logging failures shouldn't break the app

def backup_database():
    """Create a backup of the SQLite database"""
    db_path = 'revenue_management.db'
    if os.path.exists(db_path):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join('backups', f'backup_{timestamp}.db')
        shutil.copy2(db_path, backup_path)
        
        # Keep only last 10 backups
        backups = sorted(os.listdir('backups'))
        if len(backups) > 10:
            for old_backup in backups[:-10]:
                os.remove(os.path.join('backups', old_backup))
        
        return backup_path
    return None

def validate_phone_number_for_otp(phone_number):
    """
    Validate and format phone number for OTP
    
    Args:
        phone_number: Phone number to validate
    
    Returns:
        tuple: (is_valid: bool, formatted_number: str, error_message: str)
    """
    if not phone_number:
        return False, None, 'Phone number is required'
    
    # Remove spaces and dashes
    phone = phone_number.strip().replace(' ', '').replace('-', '')
    
    # Check if it's a valid Ghana number
    if phone.startswith('0') and len(phone) == 10:
        # Convert to international format
        formatted = '233' + phone[1:]
        return True, formatted, None
    elif phone.startswith('233') and len(phone) == 12:
        return True, phone, None
    elif phone.startswith('+233') and len(phone) == 13:
        return True, phone[1:], None  # Remove + prefix
    else:
        return False, None, 'Invalid phone number format. Use 0XXXXXXXXX or 233XXXXXXXXX'
    
def bulk_upload_with_update(df, model_class, unique_field, update_fields, create_callback=None):
    """
    Generic bulk upload/update function
    
    Args:
        df: DataFrame with data
        model_class: SQLAlchemy model (Property, BusinessOccupant, Product)
        unique_field: Field name to check for existing records (e.g., 'account_no')
        update_fields: List of fields to update if record exists
        create_callback: Optional function to call for new records
    
    Returns:
        dict with counts: {'created': 0, 'updated': 0, 'failed': 0, 'errors': []}
    """
    results = {
        'created': 0,
        'updated': 0,
        'failed': 0,
        'errors': []
    }
    
    for index, row in df.iterrows():
        try:
            # Get unique identifier value
            unique_value = str(row[unique_field]).strip()
            
            # Check if record exists
            existing = model_class.query.filter_by(**{unique_field: unique_value}).first()
            
            if existing:
                # UPDATE existing record
                for field in update_fields:
                    if field in row and pd.notna(row[field]):
                        setattr(existing, field, row[field])
                
                results['updated'] += 1
                app.logger.info(f"Updated {model_class.__name__} {unique_field}={unique_value}")
                
            else:
                # CREATE new record
                if create_callback:
                    new_record = create_callback(row)
                else:
                    # Default creation
                    new_record = model_class(**{
                        field: row[field] for field in update_fields if field in row
                    })
                
                db.session.add(new_record)
                results['created'] += 1
                app.logger.info(f"Created {model_class.__name__} {unique_field}={unique_value}")
            
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(f"Row {index + 2}: {str(e)}")
            app.logger.error(f"Error processing row {index + 2}: {str(e)}")
    
    return results    

def parse_numeric_value(value):
    """
    Safely parse numeric values from CSV, handling commas and various formats
    
    Args:
        value: String or numeric value to parse
    
    Returns:
        float: Parsed numeric value, or 0.0 if parsing fails
    """
    if pd.isna(value) or value in ['', None, 'N/A', '-']:
        return 0.0
    
    try:
        # Convert to string and remove common formatting
        value_str = str(value).strip()
        
        # Remove currency symbols and whitespace
        value_str = value_str.replace('GHS', '').replace('GHâ‚µ', '').replace('$', '').strip()
        
        # Remove commas (thousands separator)
        value_str = value_str.replace(',', '')
        
        # Convert to float
        return float(value_str)
    except (ValueError, TypeError, AttributeError):
        return 0.0

# ==================== UPDATED process_payment function ====================
# Replace the existing process_payment function in app.py (around line 620) with this:

def process_payment(invoice, invoice_type, form_data, files=None):
    """Centralized payment processing function with proper outstanding balance handling"""
    payment_mode = form_data.get('payment_mode')
    
    # ✅ VALIDATE GCR NUMBER IS PROVIDED
    gcr_number = form_data.get('gcr_number', '').strip()
    if not gcr_number:
        raise ValueError("GCR Number is required for all payments")
    
    # Initialize variables
    payment_type = None
    paid_by = None
    payment_amount = None
    payer_name = None
    payer_phone = None
    sender_mobile = None
    mobile_transaction = None
    bank_name = None
    bank_branch = None
    cheque_name = None
    cheque_number = None
    cheque_photo_path = None
    
    # CALCULATE OUTSTANDING BALANCE FIRST
    if invoice_type == 'Property':
        existing_payments = Payment.query.filter_by(property_invoice_id=invoice.id).all()
    else:
        existing_payments = Payment.query.filter_by(business_invoice_id=invoice.id).all()
    
    invoice_total = getattr(invoice, 'total_amount', None) or invoice.amount
    total_paid = sum(p.payment_amount for p in existing_payments)
    outstanding_balance = invoice_total - total_paid
    
    # Extract payment details based on payment mode
    if payment_mode == 'Cash':
        payment_type = form_data.get('payment_type')
        paid_by = form_data.get('paid_by')
        
        # ✅ FIX: Ensure payment_type has a default value if not provided
        if not payment_type:
            payment_type = 'Full Amount'  # Default to Full Amount
        
        # Use outstanding balance for "Full Amount"
        if payment_type == 'Full Amount':
            payment_amount = outstanding_balance
        elif payment_type == 'Overpayment':  # 🆕 NEW: Handle overpayment
            payment_amount = form_data.get('payment_amount')
            if not payment_amount:
                raise ValueError("Payment amount is required for Overpayment")
        else:  # Part Payment
            payment_amount = form_data.get('payment_amount')
            if not payment_amount:
                raise ValueError("Payment amount is required for Part Payment")
        
        payer_name = form_data.get('payer_name') if paid_by == 'Others' else None
        payer_phone = form_data.get('payer_phone') if paid_by == 'Others' else None
        
    elif payment_mode in ['MoMo', 'Mobile Money Number']:
        payment_type = form_data.get('mobile_payment_type')
        paid_by = form_data.get('mobile_paid_by')
        
        # ✅ FIX: Ensure payment_type has a default value
        if not payment_type:
            payment_type = 'Full Amount'
        
        # Use outstanding balance for "Full Amount"
        if payment_type == 'Full Amount':
            payment_amount = outstanding_balance
        elif payment_type == 'Overpayment':  # 🆕 NEW: Handle overpayment
            payment_amount = form_data.get('mobile_payment_amount')
            if not payment_amount:
                raise ValueError("Payment amount is required for Overpayment")
        else:  # Part Payment
            payment_amount = form_data.get('mobile_payment_amount')
            if not payment_amount:
                raise ValueError("Payment amount is required for Part Payment")
        
        payer_name = form_data.get('mobile_payer_name') if paid_by == 'Others' else None
        payer_phone = form_data.get('mobile_payer_phone') if paid_by == 'Others' else None
        sender_mobile = form_data.get('sender_mobile_number')
        mobile_transaction = form_data.get('mobile_transaction_id')
        
    elif payment_mode == 'Cheque':
        payment_type = form_data.get('cheque_payment_type')
        paid_by = form_data.get('cheque_paid_by')
        
        # ✅ FIX: Ensure payment_type has a default value
        if not payment_type:
            payment_type = 'Full Amount'
        
        # Use outstanding balance for "Full Amount"
        if payment_type == 'Full Amount':
            payment_amount = outstanding_balance
        elif payment_type == 'Overpayment':  # 🆕 NEW: Handle overpayment
            payment_amount = form_data.get('cheque_payment_amount')
            if not payment_amount:
                raise ValueError("Payment amount is required for Overpayment")
        else:  # Part Payment
            payment_amount = form_data.get('cheque_payment_amount')
            if not payment_amount:
                raise ValueError("Payment amount is required for Part Payment")
        
        payer_name = form_data.get('cheque_payer_name') if paid_by == 'Others' else None
        payer_phone = form_data.get('cheque_payer_phone') if paid_by == 'Others' else None
        bank_name = form_data.get('bank_name')
        bank_branch = form_data.get('bank_branch')
        cheque_name = form_data.get('cheque_name')
        cheque_number = form_data.get('cheque_number')
        
        if files and 'cheque_photo' in files:
            file = files['cheque_photo']
            if file and file.filename:
                is_valid, message = validate_file_upload(file, allowed_extensions={'png', 'jpg', 'jpeg', 'pdf'})
                if is_valid:
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"cheque_{invoice.id}_{timestamp}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    cheque_photo_path = filename
    
    # ✅ FIX: Validate that payment_type is set
    if not payment_type:
        raise ValueError("Payment type is required")
    
    # Validate payment amount
    if payment_amount:
        payment_amount = float(payment_amount)
        if payment_amount <= 0:
            raise ValueError("Payment amount must be greater than 0")
        
        # 🆕 MODIFIED: Only check max for non-overpayment types
        if payment_type != 'Overpayment' and payment_amount > outstanding_balance + 0.01:
            raise ValueError(f"Payment amount (GHS {payment_amount:,.2f}) cannot exceed outstanding balance (GHS {outstanding_balance:,.2f})")
    else:
        raise ValueError("Payment amount is required")
    
    # Validate paid_by is set
    if not paid_by:
        raise ValueError("Please specify who is making the payment")
    
    # Create payment record
    if invoice_type == 'Property':
        payment = Payment(
            property_invoice_id=invoice.id,
            business_invoice_id=None,
            invoice_no=invoice.invoice_no,
            invoice_type=invoice_type,
            payment_mode=payment_mode,
            payment_type=payment_type,
            payment_amount=payment_amount,
            gcr_number=gcr_number,
            valuation_number=form_data.get('valuation_number'),
            paid_by=paid_by,
            payer_name=payer_name,
            payer_phone=payer_phone,
            sender_mobile_number=sender_mobile,
            mobile_transaction_id=mobile_transaction,
            bank_name=bank_name,
            bank_branch=bank_branch,
            cheque_name=cheque_name,
            cheque_number=cheque_number,
            cheque_photo=cheque_photo_path,
            status='Completed',
            created_by=current_user.username if current_user.is_authenticated else 'System',
            notes=f'Overpayment: GHS {payment_amount - outstanding_balance:,.2f}' if payment_type == 'Overpayment' else None  # 🆕 NEW: Add note
        )
    else:  # Business
        payment = Payment(
            property_invoice_id=None,
            business_invoice_id=invoice.id,
            invoice_no=invoice.invoice_no,
            invoice_type=invoice_type,
            payment_mode=payment_mode,
            payment_type=payment_type,
            payment_amount=payment_amount,
            gcr_number=gcr_number,
            valuation_number=form_data.get('valuation_number'),
            paid_by=paid_by,
            payer_name=payer_name,
            payer_phone=payer_phone,
            sender_mobile_number=sender_mobile,
            mobile_transaction_id=mobile_transaction,
            bank_name=bank_name,
            bank_branch=bank_branch,
            cheque_name=cheque_name,
            cheque_number=cheque_number,
            cheque_photo=cheque_photo_path,
            status='Completed',
            created_by=current_user.username if current_user.is_authenticated else 'System',
            notes=f'Overpayment: GHS {payment_amount - outstanding_balance:,.2f}' if payment_type == 'Overpayment' else None  # 🆕 NEW: Add note
        )
    
    db.session.add(payment)
    db.session.flush()
    
    # Calculate new total paid
    new_total_paid = total_paid + payment_amount
    
    # Update invoice status
    if new_total_paid >= invoice_total:
        invoice.status = 'Paid'
    elif new_total_paid > 0:
        invoice.status = 'Partially Paid'
    else:
        invoice.status = 'Unpaid'
    
    db.session.commit()
    
    # Log the action
    log_action(
        f'Payment processed', 
        invoice_type, 
        invoice.id, 
        f'Amount: GHS {payment_amount:,.2f}, GCR: {gcr_number}, Total Paid: GHS {new_total_paid:,.2f}, Status: {invoice.status}, Type: {payment_type}'
    )
    
    return payment

def get_available_credit_balance(entity_type, entity_id, up_to_year=None):
    """
    Calculate available credit balance (overpayments) for an entity
    
    Args:
        entity_type: 'Property' or 'Business'
        entity_id: ID of the property or business
        up_to_year: Only consider invoices/payments up to this year (exclusive)
    
    Returns:
        float: Available credit balance
    """
    if entity_type == 'Property':
        # Get all invoices for this property
        invoices_query = PropertyInvoice.query.filter_by(property_id=entity_id)
        if up_to_year:
            invoices_query = invoices_query.filter(PropertyInvoice.year < up_to_year)
        invoices = invoices_query.all()
        
        total_invoice_amount = 0
        total_paid = 0
        
        for invoice in invoices:
            invoice_total = invoice.total_amount if invoice.total_amount else invoice.amount
            total_invoice_amount += invoice_total
            
            # Get payments for this invoice
            payments = Payment.query.filter_by(property_invoice_id=invoice.id).all()
            total_paid += sum(p.payment_amount for p in payments)
        
    else:  # Business
        # Get all invoices for this business
        invoices_query = BOPInvoice.query.filter_by(business_id=entity_id)
        if up_to_year:
            invoices_query = invoices_query.filter(BOPInvoice.year < up_to_year)
        invoices = invoices_query.all()
        
        total_invoice_amount = 0
        total_paid = 0
        
        for invoice in invoices:
            invoice_total = invoice.total_amount if invoice.total_amount else invoice.amount
            total_invoice_amount += invoice_total
            
            # Get payments for this invoice
            payments = Payment.query.filter_by(business_invoice_id=invoice.id).all()
            total_paid += sum(p.payment_amount for p in payments)
    
    # Credit balance is when total paid exceeds total invoiced
    credit_balance = total_paid - total_invoice_amount
    
    return credit_balance if credit_balance > 0 else 0

def find_product_by_categories(cat1, cat2, cat3, cat4, cat5, cat6):
    """Find product matching all 6 categories"""
    query = Product.query
    
    # Build filters for each category
    for i, cat_value in enumerate([cat1, cat2, cat3, cat4, cat5, cat6], 1):
        col = getattr(Product, f'category{i}')
        
        if cat_value is None:
            query = query.filter(col.is_(None))
        else:
            query = query.filter(col == cat_value)
    
    return query.first()

class InvoiceAdjustment(db.Model):
    """Track all invoice adjustments for audit purposes"""
    id = db.Column(db.Integer, primary_key=True)
    
    # Invoice reference
    property_invoice_id = db.Column(db.Integer, db.ForeignKey('property_invoice.id'), nullable=True)
    business_invoice_id = db.Column(db.Integer, db.ForeignKey('bop_invoice.id'), nullable=True)
    invoice_type = db.Column(db.String(50), nullable=False)  # 'Property' or 'Business'
    invoice_no = db.Column(db.String(50), nullable=False)
    
    # Adjustment details
    adjustment_type = db.Column(db.String(50), nullable=False)  # 'Credit', 'Penalty', 'Amount Adjustment', 'Waiver'
    original_amount = db.Column(db.Float, nullable=False)
    adjustment_amount = db.Column(db.Float, nullable=False)  # Positive = increase, Negative = decrease
    new_amount = db.Column(db.Float, nullable=False)
    
    # Justification
    reason = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    supporting_document = db.Column(db.String(200))  # Optional document upload
    
    # Approval workflow
    status = db.Column(db.String(20), default='Pending')  # 'Pending', 'Approved', 'Rejected'
    requires_approval = db.Column(db.Boolean, default=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    approval_notes = db.Column(db.Text, nullable=True)
    
    # Audit trail
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='adjustments_created')
    approver = db.relationship('User', foreign_keys=[approved_by], backref='adjustments_approved')
    
    def __repr__(self):
        return f'<InvoiceAdjustment {self.invoice_no}: {self.adjustment_type} {self.adjustment_amount}>'

# ==================== Context Processors ====================
# Add this to your context_processor section in app.py
@app.context_processor
def utility_processor():
    """Make utility functions available in templates"""
    
    def format_currency(amount):
        try:
            return f'GH₵ {amount:,.2f}'
        except Exception:
            return f'GH₵ {0:,.2f}'
    
    def format_date(date):
        return date.strftime('%Y-%m-%d %H:%M:%S') if date else ''
    
    # 🔧 ADD THIS FUNCTION
    def get_user(user_id):
        """Get user object by ID"""
        if user_id:
            return User.query.get(user_id)
        return None
    
    def get_invoice_balance(invoice, invoice_type):
        if invoice_type == 'Property':
            payments = Payment.query.filter_by(property_invoice_id=invoice.id).all()
        else:
            payments = Payment.query.filter_by(business_invoice_id=invoice.id).all()
        
        total_paid = sum((p.payment_amount or 0) for p in payments)
        invoice_total = getattr(invoice, 'total_amount', None) or getattr(invoice, 'amount', 0)
        return invoice_total - total_paid
    
    def get_year_range(start_year=2020, end_year=None):
        if end_year is None:
            end_year = datetime.now().year + 1
        return list(range(start_year, end_year + 1))
    
    def today_date():
        return datetime.now().strftime('%Y-%m-%d')
    
    def default_due_date(days=30):
        return (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
    
    def get_pending_adjustment_count():
        if current_user.is_authenticated and current_user.role == 'admin':
            return InvoiceAdjustment.query.filter_by(
                status='Pending',
                requires_approval=True
            ).count()
        return 0
    
    return dict(
        format_currency=format_currency,
        format_date=format_date,
        get_user=get_user,  # 🔧 ADD THIS LINE
        get_invoice_balance=get_invoice_balance,
        current_year=datetime.now().year,
        get_year_range=get_year_range,
        today_date=today_date,
        default_due_date=default_due_date,
        pending_count=get_pending_adjustment_count()
    )


# ==================== OTP Helper Functions ====================

def generate_otp():
    """Generate a 6-digit OTP code"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])


def format_phone_number(phone_number):
    """
    Format phone number to international format
    Returns: tuple (success: bool, formatted_number: str, error_message: str)
    """
    try:
        # Remove spaces and dashes
        phone = phone_number.strip().replace(' ', '').replace('-', '')
        
        # Handle Ghana numbers
        if phone.startswith('0') and len(phone) == 10:
            # Convert 0241234567 to +233241234567
            formatted = '+233' + phone[1:]
            return True, formatted, None
        
        elif phone.startswith('233') and len(phone) == 12:
            # Add + prefix
            formatted = '+' + phone
            return True, formatted, None
        
        elif phone.startswith('+233') and len(phone) == 13:
            # Already in correct format
            return True, phone, None
        
        else:
            return False, None, 'Invalid Ghana phone number format. Use: 0241234567 or 233241234567'
    
    except Exception as e:
        return False, None, str(e)


def send_otp_via_mock(phone_number, otp_code, amount):
    """
    Mock SMS sender - Logs OTP to console and file
    Perfect for local development and testing
    """
    try:
        success, formatted_phone, error = format_phone_number(phone_number)
        if not success:
            return False, error
        
        # Create OTP message
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"""
{'='*60}
📱 MOCK SMS - OTP CODE
{'='*60}
To: {formatted_phone}
Time: {timestamp}
OTP Code: {otp_code}
Payment Amount: GHS {amount:,.2f}
Expires: {OTP_EXPIRY_MINUTES} minutes
{'='*60}
        """
        
        # Log to console
        print(message)
        
        # Log to file
        with open(MOCK_SMS_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(message + '\n')
        
        # Highlight in terminal
        print(f"\n🎯 OTP CODE FOR TESTING: \033[92m{otp_code}\033[0m\n")
        
        return True, f'OTP logged to {MOCK_SMS_LOG_FILE} (Mock Mode)'
    
    except Exception as e:
        app.logger.error(f'Mock SMS error: {str(e)}')
        return False, f'Mock SMS error: {str(e)}'


def send_otp_via_twilio(phone_number, otp_code, amount):
    """
    Send OTP via Twilio SMS API
    Free Trial: $15 credit (~500-1000 SMS)
    """
    try:
        from twilio.rest import Client
        
        success, formatted_phone, error = format_phone_number(phone_number)
        if not success:
            return False, error
        
        # Check credentials
        if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
            return False, 'Twilio credentials not configured in .env'
        
        # Create message
        message_body = (
            f"Your AWMA payment verification code is: {otp_code}\n\n"
            f"Amount: GHS {amount:,.2f}\n"
            f"Valid for {OTP_EXPIRY_MINUTES} minutes.\n\n"
            f"Do not share this code with anyone."
        )
        
        # Initialize Twilio client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        
        # Send SMS
        message = client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=formatted_phone
        )
        
        app.logger.info(f'✅ Twilio SMS sent: {message.sid} to {formatted_phone}')
        return True, f'OTP sent via Twilio (SID: {message.sid[:10]}...)'
    
    except ImportError:
        return False, 'Twilio package not installed. Run: pip install twilio'
    
    except Exception as e:
        app.logger.error(f'Twilio error: {str(e)}')
        return False, f'Twilio error: {str(e)}'


def send_otp_via_africastalking(phone_number, otp_code, amount):
    """
    Send OTP via Africa's Talking SMS API
    Best for African countries (Ghana, Kenya, Nigeria, etc.)
    """
    try:
        import africastalking
        
        success, formatted_phone, error = format_phone_number(phone_number)
        if not success:
            return False, error
        
        # Check credentials
        if not all([AFRICASTALKING_USERNAME, AFRICASTALKING_API_KEY]):
            return False, 'Africa\'s Talking credentials not configured in .env'
        
        # Initialize SDK with explicit environment
        # Use 'sandbox' for testing, 'production' for live
        environment = 'sandbox' if AFRICASTALKING_USERNAME == 'sandbox' else 'production'
        
        africastalking.initialize(
            username=AFRICASTALKING_USERNAME, 
            api_key=AFRICASTALKING_API_KEY
        )
        sms = africastalking.SMS
        
        # Create message
        message = (
            f"Your AWMA payment verification code is: {otp_code}\n\n"
            f"Amount: GHS {amount:,.2f}\n"
            f"Valid for {OTP_EXPIRY_MINUTES} minutes."
        )
        
        # Send SMS
        response = sms.send(message, [formatted_phone])
        
        # Check response
        recipients = response['SMSMessageData']['Recipients']
        if recipients and recipients[0]['status'] == 'Success':
            app.logger.info(f'✅ Africa\'s Talking SMS sent to {formatted_phone}')
            return True, 'OTP sent via Africa\'s Talking'
        else:
            error_msg = recipients[0].get('status', 'Unknown error') if recipients else 'No response'
            app.logger.error(f'Africa\'s Talking error: {error_msg}')
            return False, f'Africa\'s Talking error: {error_msg}'
    
    except ImportError:
        return False, 'Africa\'s Talking package not installed. Run: pip install africastalking'
    
    except Exception as e:
        app.logger.error(f'Africa\'s Talking error: {str(e)}', exc_info=True)
        return False, f'Africa\'s Talking error: {str(e)}'


def send_otp_via_vonage(phone_number, otp_code, amount):
    """
    Send OTP via Vonage (Nexmo) SMS API
    Global coverage with €2 free trial
    """
    try:
        import vonage
        
        success, formatted_phone, error = format_phone_number(phone_number)
        if not success:
            return False, error
        
        # Remove + for Vonage (they use format without +)
        vonage_phone = formatted_phone.replace('+', '')
        
        # Check credentials
        if not all([VONAGE_API_KEY, VONAGE_API_SECRET]):
            return False, 'Vonage credentials not configured in .env'
        
        # Initialize Vonage client
        client = vonage.Client(key=VONAGE_API_KEY, secret=VONAGE_API_SECRET)
        sms = vonage.Sms(client)
        
        # Create message
        message = (
            f"Your AWMA payment verification code is: {otp_code}. "
            f"Amount: GHS {amount:,.2f}. Valid for {OTP_EXPIRY_MINUTES} minutes."
        )
        
        # Send SMS
        response = sms.send_message({
            "from": VONAGE_SENDER_ID,
            "to": vonage_phone,
            "text": message,
        })
        
        # Check response
        if response["messages"][0]["status"] == "0":
            app.logger.info(f'✅ Vonage SMS sent to {formatted_phone}')
            return True, 'OTP sent via Vonage'
        else:
            error_text = response["messages"][0].get("error-text", "Unknown error")
            return False, f'Vonage error: {error_text}'
    
    except ImportError:
        return False, 'Vonage package not installed. Run: pip install vonage'
    
    except Exception as e:
        app.logger.error(f'Vonage error: {str(e)}')
        return False, f'Vonage error: {str(e)}'


def send_otp_via_email_fallback(email, otp_code, amount):
    """
    Send OTP via email as fallback option
    Useful when SMS is unavailable or too expensive
    """
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        # Check email configuration
        if not all([SMTP_USERNAME, SMTP_PASSWORD]):
            return False, 'Email credentials not configured in .env'
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL or SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = 'Payment Verification Code - AWMA'
        
        body = f"""
        <html>
        <body>
            <h2>Payment Verification Code</h2>
            <p>Your payment verification code is:</p>
            <h1 style="color: #667eea; font-size: 32px;">{otp_code}</h1>
            <p><strong>Payment Amount:</strong> GHS {amount:,.2f}</p>
            <p><strong>Valid for:</strong> {OTP_EXPIRY_MINUTES} minutes</p>
            <br>
            <p style="color: #dc3545;"><strong>⚠️ Do not share this code with anyone.</strong></p>
            <br>
            <p style="color: #666; font-size: 12px;">
                This is an automated message from Ayawaso West Municipal Assembly.<br>
                If you did not request this code, please ignore this email.
            </p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        app.logger.info(f'✅ OTP sent via email to {email}')
        return True, f'OTP sent to {email}'
    
    except Exception as e:
        app.logger.error(f'Email error: {str(e)}')
        return False, f'Email error: {str(e)}'


def send_otp_sms(phone_number, otp_code, amount):
    """
    Main SMS sending function - routes to appropriate provider
    
    Args:
        phone_number: Recipient's phone number
        otp_code: 6-digit OTP code
        amount: Payment amount
    
    Returns:
        tuple: (success: bool, message: str)
    """
    provider = SMS_PROVIDER.lower()
    
    app.logger.info(f'📤 Sending OTP via {provider.upper()} to {phone_number}')
    
    if provider == 'mock':
        return send_otp_via_mock(phone_number, otp_code, amount)
    
    elif provider == 'twilio':
        return send_otp_via_twilio(phone_number, otp_code, amount)
    
    elif provider == 'africastalking':
        return send_otp_via_africastalking(phone_number, otp_code, amount)
    
    elif provider == 'vonage':
        return send_otp_via_vonage(phone_number, otp_code, amount)
    
    else:
        app.logger.error(f'Unknown SMS provider: {provider}')
        return False, f'Invalid SMS provider: {provider}. Use: mock, twilio, africastalking, or vonage'    

    
# ==================== Error Handlers ====================
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {error}')
    return render_template('errors/500.html'), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(request.url), 413

# ==================== Authentication Routes ====================
# ==================== Authentication Routes ====================
# REPLACE your existing login route with this updated version

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_temp_password:
            return redirect(url_for('change_temp_password'))
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            
            # Clear any existing flash messages
            session.pop('_flashes', None)
            
            # 🔒 Mark temporary password as used
            if user.is_temp_password:
                temp_password = TemporaryPassword.query.filter_by(
                    user_id=user.id,
                    used=False
                ).order_by(TemporaryPassword.created_at.desc()).first()
                
                if temp_password:
                    temp_password.mark_as_used()
            
            # Check if user has temporary password
            if user.is_temp_password:
                flash('You must change your temporary password before continuing.', 'warning')
                return redirect(url_for('change_temp_password'))
            
            log_action('User logged in')
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

# Keep your logout and register routes as they are

@app.route('/logout')
@login_required
def logout():
    log_action('User logged out')
    logout_user()
    
    #  FIX: Clear flash messages before adding new one
    from flask import session
    session.pop('_flashes', None)
    
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Add this route to app.py (place it with other authentication routes)

@app.route('/lock-screen', methods=['GET', 'POST'])
def lock_screen():
    """Lock screen - requires password to unlock"""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Store user info in session before locking
    session['locked_user_id'] = current_user.id
    session['locked_user_name'] = current_user.username
    session['locked_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        # Verify it's the same user
        if session.get('locked_user_id') != current_user.id:
            flash('Session mismatch. Please log in again.', 'error')
            logout_user()
            return redirect(url_for('login'))
        
        # Verify password
        if current_user.check_password(password):
            # Clear lock session data
            session.pop('locked_user_id', None)
            session.pop('locked_user_name', None)
            session.pop('locked_at', None)
            
            log_action('Screen unlocked', 'User', current_user.id)
            flash('Screen unlocked successfully!', 'success')
            return redirect(url_for('index'))
        else:
            log_action('Failed unlock attempt', 'User', current_user.id)
            flash('Incorrect password', 'error')
    
    # Don't actually log out - just show lock screen
    return render_template('lock_screen.html', 
                         username=current_user.username,
                         locked_at=session.get('locked_at'))

# ==================== Main Routes ====================
@app.route('/')
@login_required
def index():
    # Dashboard statistics
    total_properties = Property.query.count()
    total_businesses = BusinessOccupant.query.count()
    total_property_invoices = PropertyInvoice.query.count()
    total_business_invoices = BOPInvoice.query.count()
    
    paid_property_invoices = PropertyInvoice.query.filter_by(status='Paid').count()
    paid_business_invoices = BOPInvoice.query.filter_by(status='Paid').count()
    
    total_revenue = db.session.query(db.func.sum(Payment.payment_amount)).scalar() or 0
    
    recent_payments = Payment.query.order_by(Payment.payment_date.desc()).limit(10).all()
    
    return render_template('index.html',
                         total_properties=total_properties,
                         total_businesses=total_businesses,
                         total_property_invoices=total_property_invoices,
                         total_business_invoices=total_business_invoices,
                         paid_property_invoices=paid_property_invoices,
                         paid_business_invoices=paid_business_invoices,
                         total_revenue=total_revenue,
                         recent_payments=recent_payments)

# ==================== Property Routes ====================
@app.route('/property/create', methods=['GET', 'POST'])
@login_required
def create_property():
    if request.method == 'POST':
        try:
            #  FIX: Validate account number
            account_no = validate_account_number(request.form['account_no'])
            
            if Property.query.filter_by(account_no=account_no).first():
                flash(f'Error: Account number {account_no} already exists!', 'error')
                return render_template('property_create.html')
            
            #  FIX: Validate phone number
            primary_contact = None
            if request.form.get('primary_contact'):
                primary_contact = validate_phone_number(request.form['primary_contact'])

            
            #  FIX: Validate email if provided
            email = None
            if request.form.get('email'):
                email = validate_email(request.form.get('email'))
            
            #  FIX: Validate numeric values
            rateable_value = validate_numeric_input(
                request.form['rateable_value'],
                'Rateable Value',
                min_value=0,
                max_value=1000000000  # 1 billion max
            )
            
            rate_impost = validate_numeric_input(
                request.form.get('rate_impost', 0.001350),
                'Rate Impost',
                min_value=0,
                max_value=1
            )
            
            property = Property(
                primary_contact=primary_contact,
                owner_name=request.form['owner_name'].strip(),
                house_no=request.form.get('house_no', '').strip(),
                email=email,
                electoral_area=request.form['electoral_area'].strip(),
                town=request.form['town'].strip(),
                street_name=request.form.get('street_name', '').strip(),
                ghanapost_gps=request.form.get('ghanapost_gps', '').strip(),
                landmark=request.form.get('landmark', '').strip(),
                block_no=request.form['block_no'].strip(),
                parcel_no=request.form['parcel_no'].strip(),
                division_no=request.form['division_no'].strip(),
                account_no=account_no,
                category=request.form['category'].strip(),
                property_class=request.form['property_class'].strip(),
                zone=request.form['zone'].strip(),
                use_code=request.form['use_code'].strip(),
                valuation_status=request.form['valuation_status'].strip(),
                rateable_value=rateable_value,
                rate_impost=rate_impost,
                created_by=current_user.id
            )
            
            db.session.add(property)
            db.session.flush()
            
            invoice = PropertyInvoice(
                invoice_no=generate_property_invoice_no(property.id, datetime.now().year),
                property_id=property.id,
                rateable_value=property.rateable_value,
                rate_impost=property.rate_impost,
                amount=property.rateable_value * property.rate_impost,
                total_amount=property.rateable_value * property.rate_impost,
                year=datetime.now().year
            )
            db.session.add(invoice)
            db.session.commit()
            
            log_action('Property created', 'Property', property.id)
            flash('Property account created successfully!', 'success')
            return redirect(url_for('view_property', id=property.id))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating property: {str(e)}')
            flash(f'Error creating property: {str(e)}', 'error')
    
    return render_template('property_create.html')

@app.route('/property/edit/<int:id>', methods=['POST'])
@login_required
def edit_property(id):
    try:
        property = Property.query.get_or_404(id)
        
        property.primary_contact = request.form['primary_contact']
        property.owner_name = request.form['owner_name']
        property.house_no = request.form.get('house_no')
        property.email = request.form.get('email')
        property.electoral_area = request.form['electoral_area']
        property.town = request.form['town']
        property.street_name = request.form.get('street_name')
        property.ghanapost_gps = request.form.get('ghanapost_gps')
        property.landmark = request.form.get('landmark')
        property.block_no = request.form['block_no']
        property.parcel_no = request.form['parcel_no']
        property.division_no = request.form['division_no']
        property.category = request.form['category']
        property.property_class = request.form['property_class']
        property.zone = request.form['zone']
        property.use_code = request.form['use_code']
        property.valuation_status = request.form['valuation_status']
        property.rateable_value = float(request.form['rateable_value'])
        property.rate_impost = float(request.form['rate_impost'])
        
        db.session.commit()
        log_action('Property updated', 'Property', id)
        flash('Property updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating property: {str(e)}')
        flash(f'Error updating property: {str(e)}', 'error')
    
    return redirect(url_for('view_property', id=id))

@app.route('/property/delete/<int:id>', methods=['POST'])
@login_required
def delete_property(id):
    try:
        property = Property.query.get_or_404(id)
        db.session.delete(property)
        db.session.commit()
        
        log_action('Property deleted', 'Property', id)
        flash('Property deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting property: {str(e)}')
        flash(f'Error deleting property: {str(e)}', 'error')
    
    return redirect(url_for('list_properties'))

@app.route('/property/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_properties():
    """Delete multiple properties at once"""
    try:
        data = request.get_json()
        property_ids = data.get('property_ids', [])
        
        if not property_ids:
            return jsonify({
                'success': False,
                'message': 'No properties selected'
            }), 400
        
        # Verify all properties exist
        properties = Property.query.filter(Property.id.in_(property_ids)).all()
        
        if len(properties) != len(property_ids):
            return jsonify({
                'success': False,
                'message': 'Some properties not found'
            }), 404
        
        # Delete properties (cascade will delete invoices and payments)
        deleted_count = 0
        deleted_accounts = []
        
        for property in properties:
            deleted_accounts.append(property.account_no)
            db.session.delete(property)
            deleted_count += 1
        
        db.session.commit()
        
        log_action('Bulk delete properties', 
                  details=f'Deleted {deleted_count} properties: {", ".join(deleted_accounts[:10])}{"..." if len(deleted_accounts) > 10 else ""}')
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {deleted_count} properties',
            'deleted_count': deleted_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error in bulk delete properties: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'Error deleting properties: {str(e)}'
        }), 500

@app.route('/property/<int:id>')
@login_required
def view_property(id):
    property = Property.query.get_or_404(id)
    invoices = PropertyInvoice.query.filter_by(property_id=property.id).order_by(PropertyInvoice.year.desc()).all()
    return render_template('property_view.html', property=property, invoices=invoices)

@app.route('/properties')
@login_required
def list_properties():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)  # ✅ NEW: Get items per page
    search = request.args.get('search', '')
    
    # ✅ NEW: Date filters
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Validate per_page (prevent abuse)
    if per_page not in [20, 50, 100, 200]:
        per_page = 20
    
    query = Property.query
    
    # Search filter
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                Property.account_no.ilike(search_term),
                Property.owner_name.ilike(search_term),
                Property.electoral_area.ilike(search_term),
                Property.town.ilike(search_term)
            )
        )
    
    # ✅ NEW: Date filters
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Property.created_at >= date_from_obj)
        except ValueError:
            flash('Invalid start date format', 'warning')
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            # Add 1 day to include the entire end date
            date_to_obj = date_to_obj + timedelta(days=1)
            query = query.filter(Property.created_at < date_to_obj)
        except ValueError:
            flash('Invalid end date format', 'warning')
    
    pagination = query.order_by(Property.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('properties_list.html', 
                         pagination=pagination, 
                         search=search,
                         date_from=date_from,
                         date_to=date_to,
                         per_page=per_page)

# ==================== Business Routes ====================
@app.route('/business/create', methods=['GET', 'POST'])
@login_required
def create_business():
    if request.method == 'POST':
        try:
            account_no = request.form['account_no']
            if BusinessOccupant.query.filter_by(account_no=account_no).first():
                flash(f'Error: Account number {account_no} already exists!', 'error')
                return render_template('business_create.html')
            
            # Generate the 5-digit business ID
            business_id = generate_business_id()
            
            # Helper function to normalize category values
            def normalize_category(cat_value):
                """Convert empty string, 'N/A', or None to None"""
                if not cat_value or cat_value.strip() == '' or cat_value.strip().upper() == 'N/A':
                    return None
                return cat_value.strip()
            
            # Get and normalize categories from form
            category1 = normalize_category(request.form.get('category1'))
            category2 = normalize_category(request.form.get('category2'))
            category3 = normalize_category(request.form.get('category3'))
            category4 = normalize_category(request.form.get('category4'))
            category5 = normalize_category(request.form.get('category5'))
            category6 = normalize_category(request.form.get('category6'))
            
            business = BusinessOccupant(
                business_id=business_id,
                business_name=request.form['business_name'],
                business_primary_contact=request.form['business_primary_contact'],
                business_secondary_contact=request.form.get('business_secondary_contact'),
                business_website=request.form.get('business_website'),
                business_email=request.form.get('business_email'),
                owner_primary_contact=request.form['owner_primary_contact'],
                owner_name=request.form['owner_name'],
                house_no=request.form.get('house_no'),
                owner_email=request.form.get('owner_email'),
                electoral_area=request.form['electoral_area'],
                town=request.form['town'],
                street_name=request.form.get('street_name'),
                ghanapost_gps=request.form.get('ghanapost_gps'),
                landmark=request.form.get('landmark'),
                division_no=request.form['division_no'],
                property_account_no=request.form['property_account_no'],
                account_no=account_no,
                display_category=request.form['display_category'],
                category1=category1,
                category2=category2,
                category3=category3,
                category4=category4,
                category5=category5,
                category6=category6,
                created_by=current_user.id
            )
            
            db.session.add(business)
            db.session.flush()
            
            #  IMPROVED: Product matching that handles None/NULL properly
            # Build query filters dynamically
            query = Product.query
            
            # Category 1 must match (or both be None)
            if category1 is None:
                query = query.filter(Product.category1.is_(None))
            else:
                query = query.filter(Product.category1 == category1)
            
            # Categories 2-6: match value or both None
            for i in range(2, 7):
                cat_value = locals()[f'category{i}']
                if cat_value is None:
                    query = query.filter(getattr(Product, f'category{i}').is_(None))
                else:
                    query = query.filter(getattr(Product, f'category{i}') == cat_value)
            
            # Execute query to find matching product
            product = query.first()
            
            if product:
                # Create rate key for display (shows actual category values or 'N/A')
                rate_key_parts = [category1, category2, category3, category4, category5, category6]
                rate_key = '-'.join([str(p) if p else 'N/A' for p in rate_key_parts])
                
                invoice = BOPInvoice(
                    invoice_no=generate_business_invoice_no(business.business_id, datetime.now().year),
                    business_id=business.id,
                    product_name=rate_key,
                    amount=product.amount,
                    year=datetime.now().year,
                    status='Unpaid'
                )
                db.session.add(invoice)
                
                flash('Business occupant account and invoice created successfully!', 'success')
            else:
                # Log what we searched for
                search_details = f"cat1={category1}, cat2={category2}, cat3={category3}, cat4={category4}, cat5={category5}, cat6={category6}"
                app.logger.warning(f'No matching product found for business {business.business_name}. Search: {search_details}')
                flash('Business account created, but no matching product found. Please create an invoice manually or add the appropriate product rate.', 'warning')
            
            db.session.commit()
            log_action('Business created', 'Business', business.id)
            return redirect(url_for('view_business', id=business.id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating business: {str(e)}')
            flash(f'Error creating business: {str(e)}', 'error')
    
    return render_template('business_create.html')

@app.route('/business/edit/<int:id>', methods=['POST'])
@login_required
def edit_business(id):
    try:
        business = BusinessOccupant.query.get_or_404(id)
        
        business.business_name = request.form['business_name']
        business.business_primary_contact = request.form['business_primary_contact']
        business.business_secondary_contact = request.form.get('business_secondary_contact')
        business.business_website = request.form.get('business_website')
        business.business_email = request.form.get('business_email')
        business.owner_primary_contact = request.form['owner_primary_contact']
        business.owner_name = request.form['owner_name']
        business.house_no = request.form.get('house_no')
        business.owner_email = request.form.get('owner_email')
        business.electoral_area = request.form['electoral_area']
        business.town = request.form['town']
        business.street_name = request.form.get('street_name')
        business.ghanapost_gps = request.form.get('ghanapost_gps')
        business.landmark = request.form.get('landmark')
        business.division_no = request.form['division_no']
        business.property_account_no = request.form['property_account_no']
        
        db.session.commit()
        log_action('Business updated', 'Business', id)
        flash('Business updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating business: {str(e)}')
        flash(f'Error updating business: {str(e)}', 'error')
    
    return redirect(url_for('view_business', id=id))

@app.route('/business/delete/<int:id>', methods=['POST'])
@login_required
def delete_business(id):
    try:
        business = BusinessOccupant.query.get_or_404(id)
        db.session.delete(business)
        db.session.commit()
        
        log_action('Business deleted', 'Business', id)
        flash('Business deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting business: {str(e)}')
        flash(f'Error deleting business: {str(e)}', 'error')
    
    return redirect(url_for('list_businesses'))

@app.route('/business/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_businesses():
    """Delete multiple businesses at once"""
    try:
        data = request.get_json()
        business_ids = data.get('business_ids', [])
        
        if not business_ids:
            return jsonify({
                'success': False,
                'message': 'No businesses selected'
            }), 400
        
        # Verify all businesses exist
        businesses = BusinessOccupant.query.filter(BusinessOccupant.id.in_(business_ids)).all()
        
        if len(businesses) != len(business_ids):
            return jsonify({
                'success': False,
                'message': 'Some businesses not found'
            }), 404
        
        # Delete businesses (cascade will delete invoices and payments)
        deleted_count = 0
        deleted_accounts = []
        
        for business in businesses:
            deleted_accounts.append(business.account_no)
            db.session.delete(business)
            deleted_count += 1
        
        db.session.commit()
        
        log_action('Bulk delete businesses', 
                  details=f'Deleted {deleted_count} businesses: {", ".join(deleted_accounts[:10])}{"..." if len(deleted_accounts) > 10 else ""}')
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {deleted_count} businesses',
            'deleted_count': deleted_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error in bulk delete businesses: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'Error deleting businesses: {str(e)}'
        }), 500

@app.route('/business/<int:id>')
@login_required
def view_business(id):
    business = BusinessOccupant.query.get_or_404(id)
    # ADD THIS LINE to fetch invoices
    invoices = BOPInvoice.query.filter_by(business_id=business.id).order_by(BOPInvoice.year.desc()).all()
    # UPDATE THIS LINE to pass invoices to template
    return render_template('business_view.html', business=business, invoices=invoices)

@app.route('/businesses')
@login_required
def list_businesses():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)  # ✅ NEW
    search = request.args.get('search', '')
    
    # ✅ NEW: Date filters
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Validate per_page
    if per_page not in [20, 50, 100, 200]:
        per_page = 20
    
    query = BusinessOccupant.query
    
    # Search filter
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                BusinessOccupant.account_no.ilike(search_term),
                BusinessOccupant.business_name.ilike(search_term),
                BusinessOccupant.owner_name.ilike(search_term),
                BusinessOccupant.electoral_area.ilike(search_term),
                BusinessOccupant.town.ilike(search_term)
            )
        )
    
    # ✅ NEW: Date filters
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(BusinessOccupant.created_at >= date_from_obj)
        except ValueError:
            flash('Invalid start date format', 'warning')
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            date_to_obj = date_to_obj + timedelta(days=1)
            query = query.filter(BusinessOccupant.created_at < date_to_obj)
        except ValueError:
            flash('Invalid end date format', 'warning')
    
    pagination = query.order_by(BusinessOccupant.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('businesses_list.html', 
                         pagination=pagination, 
                         search=search,
                         date_from=date_from,
                         date_to=date_to,
                         per_page=per_page)

# ==================== Product Routes ====================
@app.route('/product/create', methods=['GET', 'POST'])
@login_required
def create_product():
    if request.method == 'POST':
        try:
            product = Product(
                product_name=request.form['product_name'],
                category1=request.form.get('category1'),
                category2=request.form.get('category2'),
                category3=request.form.get('category3'),
                category4=request.form.get('category4'),
                category5=request.form.get('category5'),
                category6=request.form.get('category6'),
                amount=float(request.form['amount'])
            )
            
            db.session.add(product)
            db.session.commit()
            
            log_action('Product created', 'Product', product.id)
            flash('Product created successfully!', 'success')
            return redirect(url_for('list_products'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating product: {str(e)}')
            flash(f'Error creating product: {str(e)}', 'error')
    
    return render_template('product_create.html', product={})

@app.route('/product/<int:id>')
@login_required
def view_product(id):
    """View product details"""
    product = Product.query.get_or_404(id)
    
    # Get all BOP invoices that use this product
    bop_invoices = BOPInvoice.query.filter_by(product_name=product.product_name).all()
    
    return render_template('product_view.html', 
                         product=product,
                         bop_invoices=bop_invoices)

@app.route('/product/edit/<int:id>', methods=['POST'])
@login_required
def edit_product(id):
    """Edit product details"""
    try:
        product = Product.query.get_or_404(id)
        
        # Check if product name is being changed
        new_product_name = request.form['product_name']
        if new_product_name != product.product_name:
            # Check if new name already exists
            existing = Product.query.filter_by(product_name=new_product_name).first()
            if existing:
                flash(f'Error: Product name "{new_product_name}" already exists!', 'error')
                return redirect(url_for('view_product', id=id))
        
        # Update product details
        old_name = product.product_name
        product.product_name = new_product_name
        product.category1 = request.form.get('category1')
        product.category2 = request.form.get('category2')
        product.category3 = request.form.get('category3')
        product.category4 = request.form.get('category4')
        product.category5 = request.form.get('category5')
        product.category6 = request.form.get('category6')
        product.amount = float(request.form['amount'])
        
        # If product name changed, update all BOP invoices that reference it
        if old_name != new_product_name:
            BOPInvoice.query.filter_by(product_name=old_name).update(
                {'product_name': new_product_name}
            )
        
        db.session.commit()
        log_action('Product updated', 'Product', id, f'Updated: {product.product_name}')
        flash('Product updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating product: {str(e)}')
        flash(f'Error updating product: {str(e)}', 'error')
    
    return redirect(url_for('view_product', id=id))

@app.route('/product/delete/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    try:
        product = Product.query.get_or_404(id)
        db.session.delete(product)
        db.session.commit()
        
        log_action('Product deleted', 'Product', id)
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting product: {str(e)}')
        flash(f'Error deleting product: {str(e)}', 'error')
    
    return redirect(url_for('list_products'))

@app.route('/product/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_products():
    """Delete multiple products at once"""
    try:
        data = request.get_json()
        product_ids = data.get('product_ids', [])
        
        if not product_ids:
            return jsonify({
                'success': False,
                'message': 'No products selected'
            }), 400
        
        # Verify all products exist
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        
        if len(products) != len(product_ids):
            return jsonify({
                'success': False,
                'message': 'Some products not found'
            }), 404
        
        # Delete products
        deleted_count = 0
        deleted_names = []
        
        for product in products:
            deleted_names.append(product.product_name)
            db.session.delete(product)
            deleted_count += 1
        
        db.session.commit()
        
        log_action('Bulk delete products', 
                  details=f'Deleted {deleted_count} products: {", ".join(deleted_names[:10])}{"..." if len(deleted_names) > 10 else ""}')
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {deleted_count} products',
            'deleted_count': deleted_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error in bulk delete products: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'Error deleting products: {str(e)}'
        }), 500

@app.route('/products')
@login_required
def list_products():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)  # ✅ NEW
    search = request.args.get('search', '')
    
    # ✅ NEW: Date filters
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Validate per_page
    if per_page not in [20, 50, 100, 200]:
        per_page = 20
    
    query = Product.query
    
    # Search filter
    if search:
        search_term = f'%{search}%'
        try:
            search_amount = float(search)
            query = query.filter(
                db.or_(
                    Product.product_name.ilike(search_term),
                    Product.category1.ilike(search_term),
                    Product.category2.ilike(search_term),
                    Product.category3.ilike(search_term),
                    Product.amount == search_amount
                )
            )
        except ValueError:
            query = query.filter(
                db.or_(
                    Product.product_name.ilike(search_term),
                    Product.category1.ilike(search_term),
                    Product.category2.ilike(search_term),
                    Product.category3.ilike(search_term)
                )
            )
    
    # ✅ NEW: Date filters
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Product.created_at >= date_from_obj)
        except ValueError:
            flash('Invalid start date format', 'warning')
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            date_to_obj = date_to_obj + timedelta(days=1)
            query = query.filter(Product.created_at < date_to_obj)
        except ValueError:
            flash('Invalid end date format', 'warning')
    
    pagination = query.order_by(Product.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('products_list.html', 
                         pagination=pagination, 
                         search=search,
                         date_from=date_from,
                         date_to=date_to,
                         per_page=per_page)
    
    

# ==================== Invoice Routes ====================
@app.route('/invoice/property/<int:invoice_id>')
@login_required
def view_property_invoice(invoice_id):
    """View property invoice with proper credit application and display"""
    invoice = PropertyInvoice.query.get_or_404(invoice_id)
    
    # Get all payments for this specific invoice
    payments = Payment.query.filter_by(
        property_invoice_id=invoice_id, 
        invoice_type='Property'
    ).order_by(Payment.payment_date.desc()).all()
    
    # Calculate total paid for current invoice
    total_paid = sum(p.payment_amount for p in payments)
    
    # Get invoice total
    invoice_total = getattr(invoice, 'total_amount', None) or invoice.amount
    
    # Calculate outstanding balance for current invoice (before credit)
    outstanding_balance_before_credit = invoice_total - total_paid
    
    # ========================================================================
    # STEP 1: Calculate ALL payments and invoices up to current year
    # ========================================================================
    all_invoices = PropertyInvoice.query.filter(
        PropertyInvoice.property_id == invoice.property_id,
        PropertyInvoice.year <= invoice.year
    ).order_by(PropertyInvoice.year.asc()).all()
    
    total_all_invoices = 0.0
    total_all_payments = 0.0
    
    # Track each invoice's balance and overpayments
    invoice_balances = []
    running_credit = 0.0  # Track cumulative credit
    
    for inv in all_invoices:
        inv_total = getattr(inv, 'total_amount', None) or inv.amount
        total_all_invoices += inv_total
        
        inv_payments = Payment.query.filter_by(
            property_invoice_id=inv.id,
            invoice_type='Property'
        ).all()
        inv_paid = sum(p.payment_amount for p in inv_payments)
        total_all_payments += inv_paid
        
        # Calculate balance for this invoice
        inv_balance_raw = inv_total - inv_paid
        
        # Check if this invoice has overpayment
        if inv_balance_raw < 0:
            # This invoice was overpaid - add to running credit
            overpayment = abs(inv_balance_raw)
            running_credit += overpayment
            inv_balance = 0.0  # Invoice itself is fully paid
        elif running_credit > 0 and inv_balance_raw > 0:
            # Apply accumulated credit to this invoice's balance
            credit_to_apply = min(running_credit, inv_balance_raw)
            inv_balance = inv_balance_raw - credit_to_apply
            running_credit -= credit_to_apply
        else:
            inv_balance = inv_balance_raw
        
        invoice_balances.append({
            'year': inv.year,
            'invoice_no': inv.invoice_no,
            'invoice_id': inv.id,
            'total': inv_total,
            'paid': inv_paid,
            'balance_before_credit': inv_balance_raw,
            'balance_after_auto_credit': inv_balance,
            'is_current': inv.id == invoice_id,
            'has_overpayment': inv_balance_raw < 0,
            'overpayment_amount': abs(inv_balance_raw) if inv_balance_raw < 0 else 0.0
        })
    
    # ========================================================================
    # STEP 2: Calculate total available credit and identify arrears
    # ========================================================================
    available_credit = running_credit  # Credit remaining after auto-application
    
    # Separate arrears from current invoice
    arrears_breakdown = []
    current_invoice_data = None
    total_arrears_after_credit = 0.0
    
    for inv_data in invoice_balances:
        if inv_data['is_current']:
            current_invoice_data = inv_data
        else:
            # Only add to arrears if there's still a balance after auto-credit
            if inv_data['balance_after_auto_credit'] > 0:
                arrears_breakdown.append(inv_data)
                total_arrears_after_credit += inv_data['balance_after_auto_credit']
    
    # ========================================================================
    # STEP 3: Calculate current invoice balances
    # ========================================================================
    if current_invoice_data:
        outstanding_balance_after_credit = current_invoice_data['balance_after_auto_credit']
        # Calculate credit applied to current (if any came from previous overpayments)
        credit_to_current = current_invoice_data['balance_before_credit'] - current_invoice_data['balance_after_auto_credit']
        if credit_to_current < 0:
            credit_to_current = 0.0
    else:
        outstanding_balance_after_credit = outstanding_balance_before_credit
        credit_to_current = 0.0
    
    # ========================================================================
    # STEP 4: Calculate totals
    # ========================================================================
    total_arrears_before_credit = sum(
        inv_data['balance_before_credit'] 
        for inv_data in invoice_balances 
        if not inv_data['is_current'] and inv_data['balance_before_credit'] > 0
    )
    
    # Total credit applied to arrears
    total_credit_to_arrears = total_arrears_before_credit - total_arrears_after_credit
    
    # Grand total outstanding
    grand_total_outstanding = outstanding_balance_after_credit + total_arrears_after_credit
    
    # Total credit applied
    total_credit_applied = total_all_payments - total_all_invoices
    if total_credit_applied < 0:
        total_credit_applied = 0.0
    
    remaining_credit = available_credit
    
    # ========================================================================
    # STEP 5: Get adjustments
    # ========================================================================
    adjustments = InvoiceAdjustment.query.filter_by(
        property_invoice_id=invoice_id,
        invoice_type='Property'
    ).order_by(InvoiceAdjustment.created_at.desc()).all()
    
    # ========================================================================
    # STEP 6: Log for debugging
    # ========================================================================
    app.logger.info(
        f"📊 Invoice View - {invoice.invoice_no} (Year {invoice.year}):\n"
        f"  Total Invoiced (all years ≤ {invoice.year}): GHS {total_all_invoices:,.2f}\n"
        f"  Total Paid (all years ≤ {invoice.year}): GHS {total_all_payments:,.2f}\n"
        f"  Overall Credit/Debt: GHS {total_all_payments - total_all_invoices:,.2f}\n"
        f"  \n"
        f"  === INVOICE BREAKDOWN ===\n" +
        '\n'.join([
            f"  {inv['year']}: Invoice={inv['total']:,.2f}, Paid={inv['paid']:,.2f}, "
            f"Balance={inv['balance_before_credit']:,.2f}, "
            f"After Auto-Credit={inv['balance_after_auto_credit']:,.2f}"
            + (f" [OVERPAYMENT: {inv['overpayment_amount']:,.2f}]" if inv['has_overpayment'] else "")
            for inv in invoice_balances
        ]) +
        f"\n  \n"
        f"  === CURRENT INVOICE ({invoice.year}) ===\n"
        f"  Outstanding (before credit): GHS {outstanding_balance_before_credit:,.2f}\n"
        f"  Credit Applied: GHS {credit_to_current:,.2f}\n"
        f"  Outstanding (after credit): GHS {outstanding_balance_after_credit:,.2f}\n"
        f"  \n"
        f"  === ARREARS ===\n"
        f"  Arrears (before credit): GHS {total_arrears_before_credit:,.2f}\n"
        f"  Credit Applied to Arrears: GHS {total_credit_to_arrears:,.2f}\n"
        f"  Arrears (after credit): GHS {total_arrears_after_credit:,.2f}\n"
        f"  \n"
        f"  === TOTALS ===\n"
        f"  Grand Total Outstanding: GHS {grand_total_outstanding:,.2f}\n"
        f"  Remaining Unused Credit: GHS {remaining_credit:,.2f}"
    )
    
    # ========================================================================
    # STEP 7: Render template with all data
    # ========================================================================
    return render_template('property_invoice_view.html', 
                         invoice=invoice, 
                         property=invoice.property,
                         payments=payments,
                         total_paid=total_paid,
                         outstanding_balance=outstanding_balance_after_credit,  # After credit
                         outstanding_balance_before_credit=outstanding_balance_before_credit,  # NEW
                         total_arrears=total_arrears_after_credit,
                         total_arrears_before_credit=total_arrears_before_credit,  # NEW
                         arrears_breakdown=arrears_breakdown,
                         adjustments=adjustments,
                         available_credit=available_credit,  # Total credit available
                         credit_to_current=credit_to_current,  # Credit applied to current invoice
                         total_credit_to_arrears=total_credit_to_arrears,  # Credit applied to arrears
                         remaining_credit=remaining_credit,  # Credit still unused
                         total_credit_applied=total_credit_applied,  # Total credit used
                         grand_total_outstanding=grand_total_outstanding)

# Replace the existing view_business_invoice route in app.py with this updated version:

@app.route('/invoice/business/<int:invoice_id>')
@login_required
def view_business_invoice(invoice_id):
    """View business invoice with proper credit application and display"""
    invoice = BOPInvoice.query.get_or_404(invoice_id)
    
    # Get all payments for this specific invoice
    payments = Payment.query.filter_by(
        business_invoice_id=invoice_id, 
        invoice_type='Business'
    ).order_by(Payment.payment_date.desc()).all()
    
    total_paid = sum(p.payment_amount for p in payments)
    invoice_total = getattr(invoice, 'total_amount', None) or invoice.amount
    outstanding_balance_before_credit = invoice_total - total_paid
    
    # Calculate all invoices and payments with auto-credit application
    all_invoices = BOPInvoice.query.filter(
        BOPInvoice.business_id == invoice.business_id,
        BOPInvoice.year <= invoice.year
    ).order_by(BOPInvoice.year.asc()).all()
    
    total_all_invoices = 0.0
    total_all_payments = 0.0
    invoice_balances = []
    running_credit = 0.0
    
    for inv in all_invoices:
        inv_total = getattr(inv, 'total_amount', None) or inv.amount
        total_all_invoices += inv_total
        
        inv_payments = Payment.query.filter_by(
            business_invoice_id=inv.id,
            invoice_type='Business'
        ).all()
        inv_paid = sum(p.payment_amount for p in inv_payments)
        total_all_payments += inv_paid
        
        inv_balance_raw = inv_total - inv_paid
        
        if inv_balance_raw < 0:
            overpayment = abs(inv_balance_raw)
            running_credit += overpayment
            inv_balance = 0.0
        elif running_credit > 0 and inv_balance_raw > 0:
            credit_to_apply = min(running_credit, inv_balance_raw)
            inv_balance = inv_balance_raw - credit_to_apply
            running_credit -= credit_to_apply
        else:
            inv_balance = inv_balance_raw
        
        invoice_balances.append({
            'year': inv.year,
            'invoice_no': inv.invoice_no,
            'invoice_id': inv.id,
            'total': inv_total,
            'paid': inv_paid,
            'balance_before_credit': inv_balance_raw,
            'balance_after_auto_credit': inv_balance,
            'is_current': inv.id == invoice_id,
            'has_overpayment': inv_balance_raw < 0,
            'overpayment_amount': abs(inv_balance_raw) if inv_balance_raw < 0 else 0.0
        })
    
    available_credit = running_credit
    arrears_breakdown = []
    current_invoice_data = None
    total_arrears_after_credit = 0.0
    
    for inv_data in invoice_balances:
        if inv_data['is_current']:
            current_invoice_data = inv_data
        else:
            if inv_data['balance_after_auto_credit'] > 0:
                arrears_breakdown.append(inv_data)
                total_arrears_after_credit += inv_data['balance_after_auto_credit']
    
    if current_invoice_data:
        outstanding_balance_after_credit = current_invoice_data['balance_after_auto_credit']
        credit_to_current = current_invoice_data['balance_before_credit'] - current_invoice_data['balance_after_auto_credit']
        if credit_to_current < 0:
            credit_to_current = 0.0
    else:
        outstanding_balance_after_credit = outstanding_balance_before_credit
        credit_to_current = 0.0
    
    total_arrears_before_credit = sum(
        inv_data['balance_before_credit'] 
        for inv_data in invoice_balances 
        if not inv_data['is_current'] and inv_data['balance_before_credit'] > 0
    )
    
    total_credit_to_arrears = total_arrears_before_credit - total_arrears_after_credit
    grand_total_outstanding = outstanding_balance_after_credit + total_arrears_after_credit
    
    total_credit_applied = total_all_payments - total_all_invoices
    if total_credit_applied < 0:
        total_credit_applied = 0.0
    
    remaining_credit = available_credit
    
    # Get product
    product = None
    if getattr(invoice, 'product_name', None):
        product = Product.query.filter_by(product_name=invoice.product_name).first()
    
    # Get adjustments
    adjustments = InvoiceAdjustment.query.filter_by(
        business_invoice_id=invoice_id,
        invoice_type='Business'
    ).order_by(InvoiceAdjustment.created_at.desc()).all()
    
    app.logger.info(
        f"📊 Business Invoice View - {invoice.invoice_no} (Year {invoice.year}):\n"
        f"  Available Credit: GHS {available_credit:,.2f}\n"
        f"  Credit to Current: GHS {credit_to_current:,.2f}\n"
        f"  Outstanding (after credit): GHS {outstanding_balance_after_credit:,.2f}"
    )
    
    return render_template('business_invoice_view.html', 
                         invoice=invoice, 
                         business=invoice.business,
                         payments=payments,
                         product=product,
                         total_paid=total_paid,
                         outstanding_balance=outstanding_balance_after_credit,
                         outstanding_balance_before_credit=outstanding_balance_before_credit,
                         total_arrears=total_arrears_after_credit,
                         total_arrears_before_credit=total_arrears_before_credit,
                         arrears_breakdown=arrears_breakdown,
                         adjustments=adjustments,
                         available_credit=available_credit,
                         credit_to_current=credit_to_current,
                         total_credit_to_arrears=total_credit_to_arrears,
                         remaining_credit=remaining_credit,
                         total_credit_applied=total_credit_applied,
                         grand_total_outstanding=grand_total_outstanding)
    
    
@app.route('/invoice/property/<int:invoice_id>/pay', methods=['GET'])
@login_required
def pay_property_invoice(invoice_id):
    invoice = PropertyInvoice.query.get_or_404(invoice_id)
    property = invoice.property
    
    # Get existing payments
    payments = Payment.query.filter_by(
        property_invoice_id=invoice_id, 
        invoice_type='Property'
    ).all()
    
    # Calculate totals
    total_paid = sum(p.payment_amount for p in payments)
    invoice_total = getattr(invoice, 'total_amount', None) or invoice.amount
    outstanding_balance = invoice_total - total_paid
    
    return render_template('property_invoice_pay.html', 
                         invoice=invoice, 
                         property=property,
                         payments=payments,
                         total_paid=total_paid,
                         outstanding_balance=outstanding_balance)

@app.route('/invoice/property/<int:invoice_id>/process-payment', methods=['POST'])
@login_required
def process_property_payment(invoice_id):
    """Process property invoice payment with OTP verification"""
    try:
        invoice = PropertyInvoice.query.get_or_404(invoice_id)
        
        # Get OTP ID from form
        otp_id = request.form.get('otp_id')
        
        if not otp_id:
            flash('Payment verification required. Please verify OTP first.', 'error')
            return redirect(url_for('pay_property_invoice', invoice_id=invoice_id))
        
        # Verify OTP was completed
        otp_record = OTPVerification.query.get(otp_id)
        
        if not otp_record or not otp_record.verified:
            flash('Invalid or unverified OTP. Please complete OTP verification.', 'error')
            return redirect(url_for('pay_property_invoice', invoice_id=invoice_id))
        
        # Check OTP is for this invoice
        if otp_record.invoice_id != invoice_id or otp_record.invoice_type != 'Property':
            flash('OTP verification mismatch. Please verify OTP again.', 'error')
            return redirect(url_for('pay_property_invoice', invoice_id=invoice_id))
        
        # Process the payment
        payment = process_payment(invoice, 'Property', request.form, request.files)
        
        flash('Payment processed successfully!', 'success')
        return redirect(url_for('view_property_invoice', invoice_id=invoice.id))
        
    except ValueError as ve:
        db.session.rollback()
        app.logger.error(f'Validation error processing payment: {str(ve)}')
        flash(str(ve), 'error')
        return redirect(url_for('pay_property_invoice', invoice_id=invoice_id))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error processing payment: {str(e)}', exc_info=True)
        flash(f'Error processing payment: {str(e)}', 'error')
        return redirect(url_for('pay_property_invoice', invoice_id=invoice_id))



@app.route('/invoice/business/<int:invoice_id>/pay', methods=['GET'])
@login_required
def pay_business_invoice(invoice_id):
    invoice = BOPInvoice.query.get_or_404(invoice_id)
    business = invoice.business
    
    # Get existing payments for current invoice
    payments = Payment.query.filter_by(
        business_invoice_id=invoice_id, 
        invoice_type='Business'
    ).order_by(Payment.payment_date.desc()).all()
    
    # Calculate current invoice totals
    total_paid = sum(p.payment_amount for p in payments)
    invoice_total = getattr(invoice, 'total_amount', None) or invoice.amount
    outstanding_balance = invoice_total - total_paid
    
    # Calculate arrears from previous years
    previous_invoices = BOPInvoice.query.filter(
        BOPInvoice.business_id == invoice.business_id,
        BOPInvoice.year < invoice.year
    ).all()
    
    total_arrears = 0.0
    arrears_breakdown = []
    
    for prev_invoice in previous_invoices:
        prev_invoice_total = getattr(prev_invoice, 'total_amount', None) or prev_invoice.amount
        
        prev_payments = Payment.query.filter_by(
            business_invoice_id=prev_invoice.id,
            invoice_type='Business'
        ).all()
        prev_total_paid = sum(p.payment_amount for p in prev_payments)
        
        prev_balance = prev_invoice_total - prev_total_paid
        
        if prev_balance > 0:
            total_arrears += prev_balance
            arrears_breakdown.append({
                'year': prev_invoice.year,
                'invoice_no': prev_invoice.invoice_no,
                'total': prev_invoice_total,
                'paid': prev_total_paid,
                'balance': prev_balance
            })
    
    return render_template('business_invoice_pay.html', 
                         invoice=invoice, 
                         business=business,
                         payments=payments,
                         total_paid=total_paid,
                         outstanding_balance=outstanding_balance,
                         total_arrears=total_arrears,
                         arrears_breakdown=arrears_breakdown)

@app.route('/invoice/business/<int:invoice_id>/process-payment', methods=['POST'])
@login_required
def process_business_payment(invoice_id):
    """Process business invoice payment with OTP verification"""
    try:
        invoice = BOPInvoice.query.get_or_404(invoice_id)
        
        # Get OTP ID from form
        otp_id = request.form.get('otp_id')
        
        if not otp_id:
            flash('Payment verification required. Please verify OTP first.', 'error')
            return redirect(url_for('pay_business_invoice', invoice_id=invoice_id))
        
        # Verify OTP was completed
        otp_record = OTPVerification.query.get(otp_id)
        
        if not otp_record or not otp_record.verified:
            flash('Invalid or unverified OTP. Please complete OTP verification.', 'error')
            return redirect(url_for('pay_business_invoice', invoice_id=invoice_id))
        
        # Check OTP is for this invoice
        if otp_record.invoice_id != invoice_id or otp_record.invoice_type != 'Business':
            flash('OTP verification mismatch. Please verify OTP again.', 'error')
            return redirect(url_for('pay_business_invoice', invoice_id=invoice_id))
        
        # Process the payment
        payment = process_payment(invoice, 'Business', request.form, request.files)
        
        flash('Payment processed successfully!', 'success')
        return redirect(url_for('view_business_invoice', invoice_id=invoice.id))
        
    except ValueError as ve:
        db.session.rollback()
        app.logger.error(f'Validation error processing payment: {str(ve)}')
        flash(str(ve), 'error')
        return redirect(url_for('pay_business_invoice', invoice_id=invoice_id))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error processing payment: {str(e)}', exc_info=True)
        flash(f'Error processing payment: {str(e)}', 'error')
        return redirect(url_for('pay_business_invoice', invoice_id=invoice_id))

@app.route('/invoice/property/<int:invoice_id>/print')
@login_required
def print_property_invoice(invoice_id):
    """Print business invoice with arrears calculation"""
    invoice = PropertyInvoice.query.get_or_404(invoice_id)
    property = invoice.property
    
    # Get payments for current invoice
    payments = Payment.query.filter_by(
        property_invoice_id=invoice_id,
        invoice_type='Property'
    ).all()
    total_paid = sum(p.payment_amount for p in payments)
    
    # Calculate arrears from previous years
    previous_invoices = PropertyInvoice.query.filter(
        PropertyInvoice.property_id == invoice.property_id,
        PropertyInvoice.year < invoice.year
    ).all()
    
    total_arrears = 0.0
    arrears_breakdown = []
    
    for prev_invoice in previous_invoices:
        prev_invoice_total = getattr(prev_invoice, 'total_amount', None) or prev_invoice.amount
        
        prev_payments = Payment.query.filter_by(
            business_invoice_id=prev_invoice.id,
            invoice_type='Property'
        ).all()
        prev_total_paid = sum(p.payment_amount for p in prev_payments)
        
        prev_balance = prev_invoice_total - prev_total_paid
        
        if prev_balance > 0:
            total_arrears += prev_balance
            arrears_breakdown.append({
                'year': prev_invoice.year,
                'invoice_no': prev_invoice.invoice_no,
                'total': prev_invoice_total,
                'paid': prev_total_paid,
                'balance': prev_balance
            })
    
    # Get product if available
    product = None
    if getattr(invoice, 'product_name', None):
        product = Product.query.filter_by(product_name=invoice.product_name).first()
    
    #  FIX: Pass ALL required variables to template
    return render_template('property_invoice_print.html', 
                         invoice=invoice, 
                         property=property, 
                         product=product,
                         total_paid=total_paid,
                         total_arrears=total_arrears,
                         arrears_breakdown=arrears_breakdown)

# Replace the print_business_invoice route in app.py with this updated version:

@app.route('/invoice/business/<int:invoice_id>/print')
@login_required
def print_business_invoice(invoice_id):
    """Print business invoice with arrears calculation"""
    invoice = BOPInvoice.query.get_or_404(invoice_id)
    business = invoice.business
    
    # Get payments for current invoice
    payments = Payment.query.filter_by(
        business_invoice_id=invoice_id,
        invoice_type='Business'
    ).all()
    total_paid = sum(p.payment_amount for p in payments)
    
    # Calculate arrears from previous years
    previous_invoices = BOPInvoice.query.filter(
        BOPInvoice.business_id == invoice.business_id,
        BOPInvoice.year < invoice.year
    ).all()
    
    total_arrears = 0.0
    arrears_breakdown = []
    
    for prev_invoice in previous_invoices:
        prev_invoice_total = getattr(prev_invoice, 'total_amount', None) or prev_invoice.amount
        
        prev_payments = Payment.query.filter_by(
            business_invoice_id=prev_invoice.id,
            invoice_type='Business'
        ).all()
        prev_total_paid = sum(p.payment_amount for p in prev_payments)
        
        prev_balance = prev_invoice_total - prev_total_paid
        
        if prev_balance > 0:
            total_arrears += prev_balance
            arrears_breakdown.append({
                'year': prev_invoice.year,
                'invoice_no': prev_invoice.invoice_no,
                'total': prev_invoice_total,
                'paid': prev_total_paid,
                'balance': prev_balance
            })
    
    # Get product if available
    product = None
    if getattr(invoice, 'product_name', None):
        product = Product.query.filter_by(product_name=invoice.product_name).first()
    
    #  FIX: Pass ALL required variables to template
    return render_template('business_invoice_print.html', 
                         invoice=invoice, 
                         business=business, 
                         product=product,
                         total_paid=total_paid,
                         total_arrears=total_arrears,
                         arrears_breakdown=arrears_breakdown)

def generate_invoice_no(prefix="INV", max_retries=10):
    """Generate a unique invoice number with collision detection"""
    for attempt in range(max_retries):
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        # Use secrets for cryptographically secure random numbers
        random_num = secrets.randbelow(10000)
        invoice_no = f"{prefix}-{timestamp}-{random_num:04d}"
        
        # Check if invoice number already exists in either table
        prop_exists = PropertyInvoice.query.filter_by(invoice_no=invoice_no).first()
        bop_exists = BOPInvoice.query.filter_by(invoice_no=invoice_no).first()
        
        if not prop_exists and not bop_exists:
            return invoice_no
        
        # If collision detected, log and retry
        app.logger.warning(f'Invoice number collision detected: {invoice_no}, retrying...')
    
    # If all retries failed, raise an exception
    raise Exception(f"Failed to generate unique invoice number after {max_retries} attempts")

@app.route('/property/invoice/create/<int:id>', methods=['GET', 'POST'])
@login_required
def create_invoice(id):
    # 1. Fetch main entities and existing invoices (common to GET and POST)
    property = Property.query.get_or_404(id)
    existing_invoices = PropertyInvoice.query.filter_by(property_id=property.id).all()

    if request.method == 'POST':
        try:
            # --- Extract & Convert Form Data ---
            year = int(request.form.get('invoice_year'))
            generation_type = request.form.get('generation_type')
            amount_type = request.form.get('amount_type')
            
            # Validate required fields
            if not year or not generation_type or not amount_type:
                flash('Please fill in all required fields.', 'error')
                return redirect(url_for('create_invoice', id=property.id))
            
            # Use 0.0 as default for safety
            tax_rate_percent = float(request.form.get('tax_rate', 0.0))
            tax_rate = tax_rate_percent / 100  # Convert to decimal (e.g., 17.5 -> 0.175)
            
            # Convert date strings to date objects
            invoice_date = datetime.strptime(request.form.get('invoice_date'), '%Y-%m-%d').date()
            due_date = datetime.strptime(request.form.get('due_date'), '%Y-%m-%d').date()
            description = request.form.get('description', '')
            
            # --- Core Logic: Calculate Base Amount ---
            base_amount = 0.0
            rate_impost_used = property.rate_impost  # Default to property's rate_impost
            
            if amount_type == 'fixed_amount':
                # **Fixed Amount:** Use the user-keyed amount
                base_amount_input = request.form.get('amount')
                if not base_amount_input:
                    flash('Fixed amount is required when Fixed Amount calculation is selected.', 'error')
                    return redirect(url_for('create_invoice', id=property.id))
                base_amount = float(base_amount_input)
            
            elif amount_type == 'fee_fixing':
                # **Fee Fixing:** Calculate based on property rateable value and rate impost
                if property.rateable_value is None:
                    flash('Property Rateable Value is missing. Cannot calculate Fee Fixing amount.', 'error')
                    return redirect(url_for('create_invoice', id=property.id))
                
                if property.rate_impost is None:
                    flash('Property Rate Impost is missing. Cannot calculate Fee Fixing amount.', 'error')
                    return redirect(url_for('create_invoice', id=property.id))
                
                base_amount = property.rateable_value * property.rate_impost
                rate_impost_used = property.rate_impost
            
            # --- Final Calculations ---
            tax_amount = base_amount * tax_rate
            final_amount = base_amount + tax_amount
            
            # --- Generation/Update Logic ---
            existing_invoice = PropertyInvoice.query.filter_by(
                property_id=property.id, 
                year=year
            ).first()

            if generation_type == 'generate_new':
                # **Rule 1: An invoice with the year already generated, can't be generated again but only updated.**
                if existing_invoice:
                    flash(f'Invoice for {year} already exists (No: {existing_invoice.invoice_no}). Select "Update Existing Bill" to modify it.', 'error')
                    return redirect(url_for('create_invoice', id=property.id))

                new_invoice = PropertyInvoice(
                    invoice_no=generate_property_invoice_no(property.id, year),
                    property_id=property.id,
                    year=year,
                    product_id=None,  # Not using product_id for property invoices
                    rateable_value=property.rateable_value,
                    rate_impost=rate_impost_used,
                    amount=round(base_amount, 2),
                    tax_rate=tax_rate_percent,  # Store as percentage (e.g., 17.5)
                    tax_amount=round(tax_amount, 2),
                    total_amount=round(final_amount, 2),
                    invoice_date=invoice_date,
                    due_date=due_date,
                    description=description,
                    status='Unpaid'
                )
                db.session.add(new_invoice)
                db.session.commit()
                
                log_action('Property invoice created', 'PropertyInvoice', new_invoice.id, 
                          f'Year: {year}, Amount: GHS {base_amount:.2f}')
                flash(f'New Property Invoice {new_invoice.invoice_no} generated successfully!', 'success')
                return redirect(url_for('view_property_invoice', invoice_id=new_invoice.id))

            elif generation_type == 'update_existing':
                if not existing_invoice:
                    flash(f'No existing invoice found for year {year}. Please use "Generate New Bill" to create one.', 'warning')
                    return redirect(url_for('create_invoice', id=property.id))
                
                # **Update:** Apply the new calculated or fixed amount
                existing_invoice.rateable_value = property.rateable_value
                existing_invoice.rate_impost = rate_impost_used
                existing_invoice.amount = round(base_amount, 2)
                existing_invoice.tax_rate = tax_rate_percent
                existing_invoice.tax_amount = round(tax_amount, 2)
                existing_invoice.total_amount = round(final_amount, 2)
                existing_invoice.invoice_date = invoice_date
                existing_invoice.due_date = due_date
                existing_invoice.description = description

                db.session.commit()
                
                log_action('Property invoice updated', 'PropertyInvoice', existing_invoice.id,
                          f'Year: {year}, New Amount: GHS {base_amount:.2f}')
                flash(f'Property Invoice {existing_invoice.invoice_no} for {year} updated successfully!', 'success')
                return redirect(url_for('view_property_invoice', invoice_id=existing_invoice.id))
            
            else:
                flash('Invalid generation type submitted.', 'error')
                
        except ValueError as e:
            db.session.rollback()
            app.logger.error(f"ValueError in create_invoice: {str(e)}")
            flash(f'Data validation error: {str(e)}', 'error')
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Unexpected error in create_invoice POST: {str(e)}", exc_info=True)
            flash(f'An unexpected error occurred: {str(e)}', 'error')
            
        # Fallback redirect in case of any error during POST
        return redirect(url_for('create_invoice', id=property.id))

    # GET request handler (Renders the form)
    return render_template('property_invoice_form.html', 
                           property=property, 
                           existing_invoices=existing_invoices)
    
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy import distinct, func # Ensure 'distinct' is imported
# ... (other imports) ...

@app.route('/business/invoice/create/<int:id>', methods=['GET', 'POST'])
@login_required
def create_business_invoice(id):
    """
    Create or update an invoice for a business occupant.
    The amount is determined either by business categories (fee fixing) or a fixed manual amount.
    """
    # =========================================================
    # 1. SETUP & CATEGORY FETCHING (MUST RUN FIRST)
    # =========================================================
    business = BusinessOccupant.query.get_or_404(id)
    existing_invoices = BOPInvoice.query.filter_by(business_id=business.id).all()

    def fetch_unique_categories():
        categories = {}
        # List of category column names in the Product model
        category_cols = ['category1', 'category2', 'category3', 'category4', 'category5', 'category6']
        
        for i, col in enumerate(category_cols, 1):
            # Query the distinct values for the current column
            distinct_values = [
                value[0] 
                for value in db.session.query(distinct(getattr(Product, col))).all() 
                if value[0] is not None and value[0] != ''
            ]
            categories[f'category{i}'] = sorted(distinct_values)

        return categories
    
    # Define 'categories' here, before any 'if/else' checks
    unique_categories = fetch_unique_categories()
    
    # Base dictionary for template variables (passed in every render)
    template_vars = {
        'business': business, 
        'existing_invoices': existing_invoices,
        'categories': unique_categories
    }

    # =========================================================
    # 2. POST REQUEST HANDLING (Form Submission Logic)
    # =========================================================
    if request.method == 'POST':
        try:
            # Extract core form data
            year_input = request.form.get('invoice_year')
            if not year_input:
                flash('Invoice year is required.', 'danger')
                return redirect(url_for('create_business_invoice', id=business.id))
            
            year = int(year_input)
            
            # Allow any year from 2000 to current_year + 5
            current_year = datetime.now().year
            if year < 2000 or year > current_year + 5:
                flash(f'Invalid year. Please select a year between 2000 and {current_year + 5}.', 'danger')
                return redirect(url_for('create_business_invoice', id=business.id))
            
            generation_type = request.form.get('generation_type')
            amount_type = request.form.get('amount_type')
            
            # Validate required fields
            if not generation_type:
                flash('Please select an action type (Generate New or Update Existing).', 'danger')
                return redirect(url_for('create_business_invoice', id=business.id))
            
            if not amount_type:
                flash('Please select an amount calculation method.', 'danger')
                return redirect(url_for('create_business_invoice', id=business.id))
            
            # Validate amount_type
            if amount_type not in ['fixed_amount', 'fee_fixing']:
                flash('Invalid amount calculation method submitted.', 'danger')
                return redirect(url_for('create_business_invoice', id=business.id))
            
            amount = None
            rate_key = 'FixedRate'  # Default key for fixed amount

            # --- Determine Amount Source ---
            if amount_type == 'fixed_amount':
                try:
                    amount_input = request.form.get('amount')
                    if not amount_input:
                        flash('Fixed amount is required when using Fixed Amount calculation.', 'danger')
                        return redirect(url_for('create_business_invoice', id=business.id))
                    
                    amount = float(amount_input)
                    if amount <= 0:
                        flash('Amount must be greater than zero.', 'danger')
                        return redirect(url_for('create_business_invoice', id=business.id))
                        
                except (ValueError, TypeError):
                    flash('Invalid value for Fixed Amount. Must be a valid positive number.', 'danger')
                    return redirect(url_for('create_business_invoice', id=business.id))
                
            elif amount_type == 'fee_fixing':
                #  FIXED: Improved normalize function to handle '-' character
                def normalize_category(cat_value):
                    """Convert NONE, empty string, None, '-', or whitespace-only to None for comparison"""
                    if not cat_value:
                        return None
                    # Convert to string and strip whitespace
                    cat_str = str(cat_value).strip()
                    # Check if it's an empty/placeholder value
                    if cat_str in ['NONE', '', 'N/A', '-']:
                        return None
                    return cat_str
                
                # Get business categories
                business_cat1 = normalize_category(business.category1)
                business_cat2 = normalize_category(business.category2)
                business_cat3 = normalize_category(business.category3)
                business_cat4 = normalize_category(business.category4)
                business_cat5 = normalize_category(business.category5)
                business_cat6 = normalize_category(business.category6)
                
                # Log what we're searching for (for debugging)
                search_details = f"cat1={business_cat1}, cat2={business_cat2}, cat3={business_cat3}, cat4={business_cat4}, cat5={business_cat5}, cat6={business_cat6}"
                app.logger.info(f'🔍 Searching for product matching: {search_details}')
                
                # Validate that at least category1 exists
                if not business_cat1:
                    flash('Business Category 1 is required for fee fixing calculation. Please update the business record first.', 'error')
                    return redirect(url_for('create_business_invoice', id=business.id))
                
                #  FIXED: Build filter conditions with proper NULL handling
                filters = []
                
                # Category 1 must match exactly
                if business_cat1 is None:
                    filters.append(Product.category1.is_(None))
                else:
                    filters.append(Product.category1 == business_cat1)
                
                # Categories 2-6: match both explicit values and NULL
                for i in range(2, 7):
                    cat_value = locals()[f'business_cat{i}']
                    col = getattr(Product, f'category{i}')
                    
                    if cat_value is None:
                        filters.append(col.is_(None))
                    else:
                        filters.append(col == cat_value)
                
                #  FIXED: Log all products that match category1 for debugging
                app.logger.info('🔍 Checking products in database...')
                all_products = Product.query.filter(
                    Product.category1 == business_cat1
                ).all()
                
                app.logger.info(f'📦 Found {len(all_products)} products with category1={business_cat1}')
                for prod in all_products:
                    prod_cats = {
                        'cat1': normalize_category(prod.category1),
                        'cat2': normalize_category(prod.category2),
                        'cat3': normalize_category(prod.category3),
                        'cat4': normalize_category(prod.category4),
                        'cat5': normalize_category(prod.category5),
                        'cat6': normalize_category(prod.category6)
                    }
                    app.logger.info(f'  - {prod.product_name}: {prod_cats}')
                
                # Find matching product
                product = Product.query.filter(*filters).first()
                
                if not product:
                    # No matching product found
                    app.logger.warning(f'❌ No matching product found for business {business.business_name}.')
                    app.logger.warning(f'   Search criteria: {search_details}')
                    
                    # Check if there are products with matching first 2 categories (for helpful error message)
                    if business_cat2:
                        partial_match = Product.query.filter(
                            Product.category1 == business_cat1,
                            Product.category2 == business_cat2
                        ).first()
                    else:
                        partial_match = Product.query.filter(
                            Product.category1 == business_cat1,
                            Product.category2.is_(None)
                        ).first()
                    
                    if partial_match:
                        partial_cats = {
                            'cat1': normalize_category(partial_match.category1),
                            'cat2': normalize_category(partial_match.category2),
                            'cat3': normalize_category(partial_match.category3),
                            'cat4': normalize_category(partial_match.category4),
                            'cat5': normalize_category(partial_match.category5),
                            'cat6': normalize_category(partial_match.category6)
                        }
                        flash(f'No exact product match found. Found similar product: "{partial_match.product_name}" with categories {partial_cats}, but it does not match all your business categories. Please verify business categories or use Fixed Amount.', 'error')
                    else:
                        flash(f'No matching product rate found for these business categories: [{search_details}]. Please use Fixed Amount instead or contact administrator to add the appropriate product rate.', 'error')
                    
                    return redirect(url_for('create_business_invoice', id=business.id))
                
                #  Product found - use its amount
                amount = product.amount
                
                # Create rate key from categories (for display/tracking)
                rate_key_parts = [business_cat1, business_cat2, business_cat3, business_cat4, business_cat5, business_cat6]
                rate_key = '-'.join([str(p) if p else 'N/A' for p in rate_key_parts])
                
                app.logger.info(f' Product match found: {product.product_name} (Amount: GH₵ {amount:.2f})')
            
            # --- Extract additional form fields ---
            tax_rate_input = request.form.get('tax_rate', '0.0')
            try:
                tax_rate_percent = float(tax_rate_input)
                if tax_rate_percent < 0 or tax_rate_percent > 100:
                    flash('Tax rate must be between 0 and 100.', 'danger')
                    return redirect(url_for('create_business_invoice', id=business.id))
            except (ValueError, TypeError):
                flash('Invalid tax rate. Must be a valid number.', 'danger')
                return redirect(url_for('create_business_invoice', id=business.id))
            
            tax_rate = tax_rate_percent / 100  # Convert to decimal
            tax_amount = amount * tax_rate
            total_amount = amount + tax_amount
            
            # Convert date strings to date objects
            try:
                invoice_date_str = request.form.get('invoice_date')
                due_date_str = request.form.get('due_date')
                
                if not invoice_date_str or not due_date_str:
                    flash('Invoice date and due date are required.', 'danger')
                    return redirect(url_for('create_business_invoice', id=business.id))
                
                invoice_date = datetime.strptime(invoice_date_str, '%Y-%m-%d').date()
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                
                # Validate that due date is after invoice date
                if due_date < invoice_date:
                    flash('Due date cannot be before invoice date.', 'warning')
                    
            except ValueError:
                flash('Invalid date format. Please use the date picker.', 'danger')
                return redirect(url_for('create_business_invoice', id=business.id))
            
            description = request.form.get('description', '').strip()
            
            # --- Check for existing invoice ---
            existing_invoice = BOPInvoice.query.filter_by(
                business_id=business.id,
                year=year,
                product_name=rate_key
            ).first()

            # --- Generation/Update Logic ---
            if generation_type == 'generate_new':
                if existing_invoice:
                    flash(f'Invoice for {year} with the selected configuration already exists (Invoice No: {existing_invoice.invoice_no}). Select "Update Existing Bill" to modify it.', 'danger')
                    return redirect(url_for('create_business_invoice', id=business.id))

                # Generate new invoice
                new_invoice = BOPInvoice(
                    invoice_no=generate_business_invoice_no(business.business_id, year),
                    business_id=business.id,
                    product_name=rate_key,
                    amount=round(amount, 2),
                    tax_rate=tax_rate_percent,
                    tax_amount=round(tax_amount, 2),
                    total_amount=round(total_amount, 2),
                    year=year,
                    status='Unpaid',
                    invoice_date=invoice_date,
                    due_date=due_date,
                    description=description
                )
                db.session.add(new_invoice)
                db.session.commit()
                
                log_action('Business invoice created', 'BOPInvoice', new_invoice.id, 
                          f'Year: {year}, Amount: GHS {amount:.2f}, Rate Key: {rate_key}')
                flash(f'New Business Invoice {new_invoice.invoice_no} for year {year} generated successfully!', 'success')
                return redirect(url_for('view_business_invoice', invoice_id=new_invoice.id))

            elif generation_type == 'update_existing':
                if not existing_invoice:
                    flash(f'No existing invoice found for year {year} with the selected configuration. Please use "Generate New Bill" to create one.', 'warning')
                    return redirect(url_for('create_business_invoice', id=business.id))
                
                # Update existing invoice
                existing_invoice.product_name = rate_key
                existing_invoice.amount = round(amount, 2)
                existing_invoice.tax_rate = tax_rate_percent
                existing_invoice.tax_amount = round(tax_amount, 2)
                existing_invoice.total_amount = round(total_amount, 2)
                existing_invoice.invoice_date = invoice_date
                existing_invoice.due_date = due_date
                existing_invoice.description = description
                
                db.session.commit()
                
                log_action('Business invoice updated', 'BOPInvoice', existing_invoice.id,
                          f'Year: {year}, New Amount: GHS {amount:.2f}')
                flash(f'Business Invoice {existing_invoice.invoice_no} for year {year} updated successfully!', 'success')
                return redirect(url_for('view_business_invoice', invoice_id=existing_invoice.id))
            
            else:
                flash('Invalid generation type submitted.', 'danger')
        
        except ValueError as ve:
            db.session.rollback()
            app.logger.error(f"ValueError in create_business_invoice: {str(ve)}")
            flash(f'Data validation error: {str(ve)}', 'danger')
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Unexpected error in create_business_invoice POST: {str(e)}", exc_info=True)
            flash('An unexpected error occurred. Please contact support.', 'danger')
            
        # All failed POST attempts redirect back to the GET route
        return redirect(url_for('create_business_invoice', id=business.id))

    # =========================================================
    # 3. GET REQUEST HANDLING (Render Form)
    # =========================================================
    return render_template('business_invoice_form.html', **template_vars)

# ==================== Payment Routes ====================
@app.route('/payments')
@login_required
def list_payments():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)  # ✅ NEW
    search = request.args.get('search', '')
    
    # ✅ NEW: Date filters
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Validate per_page
    if per_page not in [20, 50, 100, 200]:
        per_page = 20
    
    query = Payment.query
    
    # Search filter
    if search:
        query = query.filter(
            db.or_(
                Payment.invoice_no.ilike(f'%{search}%'),
                Payment.payer_name.ilike(f'%{search}%'),
                Payment.mobile_transaction_id.ilike(f'%{search}%'),
                Payment.gcr_number.ilike(f'%{search}%')
            )
        )
    
    # ✅ NEW: Date filters
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Payment.payment_date >= date_from_obj)
        except ValueError:
            flash('Invalid start date format', 'warning')
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            date_to_obj = date_to_obj + timedelta(days=1)
            query = query.filter(Payment.payment_date < date_to_obj)
        except ValueError:
            flash('Invalid end date format', 'warning')
    
    pagination = query.order_by(Payment.payment_date.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('payments_list.html', 
                         pagination=pagination, 
                         search=search,
                         date_from=date_from,
                         date_to=date_to,
                         per_page=per_page)

@app.route('/payment/<int:payment_id>')
@login_required
def view_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    return render_template('payment_view.html', payment=payment)

# ==================== Bulk Upload Routes ====================
@app.route('/property/bulk-upload', methods=['GET', 'POST'])
@login_required
def bulk_upload_properties():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        is_valid, message = validate_file_upload(file, allowed_extensions={'csv', 'xlsx'})
        
        if not is_valid:
            flash(message, 'error')
            return redirect(request.url)
        
        try:
            # Read file based on extension
            if file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            else:
                df = pd.read_excel(file)
            
            # Required columns validation
            required_columns = [
                'account_no', 'owner_name', 
                'electoral_area', 'town', 'block_no', 'parcel_no',
                'division_no', 'category', 'property_class', 'zone',
                'use_code', 'valuation_status', 'rateable_value'
            ]
            
            missing_columns = set(required_columns) - set(df.columns)
            if missing_columns:
                flash(f'Missing required columns: {", ".join(missing_columns)}', 'error')
                return redirect(request.url)
            
            # Clean data - convert to string and strip whitespace
            df = df.fillna('')
            
            # Convert account_no to string and strip whitespace
            df['account_no'] = df['account_no'].astype(str).str.strip().str.upper()
            
            # Remove any completely empty rows
            df = df[df['account_no'] != '']
            
            # Check for duplicate account numbers in the uploaded file
            duplicate_mask = df.duplicated('account_no', keep=False)
            duplicate_accounts = df[duplicate_mask]['account_no'].unique()
            
            if len(duplicate_accounts) > 0:
                duplicate_rows = []
                for acc_no in duplicate_accounts:
                    rows = df[df['account_no'] == acc_no].index.tolist()
                    duplicate_rows.append(f"{acc_no} (rows: {', '.join([str(r+2) for r in rows])})")
                
                flash(f'Duplicate account numbers found in file: {"; ".join(duplicate_rows[:10])}', 'error')
                return redirect(request.url)
            
            # 🔧 NEW: Get update mode from form
            update_mode = request.form.get('update_mode', 'skip')  # 'skip', 'update', or 'fail'
            
            # Check for existing account numbers in database
            existing_properties = Property.query.filter(
                Property.account_no.in_(df['account_no'].tolist())
            ).all()
            existing_accounts = {p.account_no: p for p in existing_properties}
            
            # 🔧 NEW: Handle 'fail' mode
            if update_mode == 'fail' and existing_accounts:
                flash(f'❌ Strict Mode: {len(existing_accounts)} duplicate account(s) found: {", ".join(list(existing_accounts.keys())[:10])}{"..." if len(existing_accounts) > 10 else ""}', 'error')
                return redirect(request.url)
            
            # Counters
            success_count = 0   # New properties created
            updated_count = 0   # Existing properties updated
            skipped_count = 0   # Existing properties skipped
            error_count = 0
            processing_errors = []
            
            # Process records
            with transaction_scope():
                for index, row in df.iterrows():
                    try:
                        account_no = str(row['account_no']).strip().upper()
                        
                        # Check if property exists
                        existing_property = existing_accounts.get(account_no)
                        
                        if existing_property:
                            if update_mode == 'update':
                                # 🔧 UPDATE existing property
                                # Get and validate optional fields
                                primary_contact = str(row.get('primary_contact', '')).strip() if row.get('primary_contact') else None
                                email = str(row.get('email', '')).strip() if row.get('email') else None
                                
                                try:
                                    rateable_value = float(row.get('rateable_value', 0))
                                except (ValueError, TypeError):
                                    rateable_value = 0.0
                                
                                try:
                                    rate_impost = float(row.get('rate_impost', 0.001350))
                                except (ValueError, TypeError):
                                    rate_impost = 0.001350
                                
                                # Update all fields
                                existing_property.primary_contact = primary_contact
                                existing_property.owner_name = str(row['owner_name']).strip()
                                existing_property.house_no = str(row.get('house_no', '')).strip()
                                existing_property.email = email
                                existing_property.electoral_area = str(row['electoral_area']).strip()
                                existing_property.town = str(row['town']).strip()
                                existing_property.street_name = str(row.get('street_name', '')).strip()
                                existing_property.ghanapost_gps = str(row.get('ghanapost_gps', '')).strip()
                                existing_property.landmark = str(row.get('landmark', '')).strip()
                                existing_property.block_no = str(row['block_no']).strip()
                                existing_property.parcel_no = str(row['parcel_no']).strip()
                                existing_property.division_no = str(row['division_no']).strip()
                                existing_property.category = str(row['category']).strip()
                                existing_property.property_class = str(row['property_class']).strip()
                                existing_property.zone = str(row['zone']).strip()
                                existing_property.use_code = str(row['use_code']).strip()
                                existing_property.valuation_status = str(row['valuation_status']).strip()
                                existing_property.rateable_value = rateable_value
                                existing_property.rate_impost = rate_impost
                                
                                updated_count += 1
                                app.logger.info(f"Updated property: {account_no}")
                                
                            else:  # skip mode
                                skipped_count += 1
                                continue
                        
                        else:
                            # 🔧 CREATE new property
                            primary_contact = str(row.get('primary_contact', '')).strip() if row.get('primary_contact') else None
                            email = str(row.get('email', '')).strip() if row.get('email') else None
                            
                            try:
                                rateable_value = float(row.get('rateable_value', 0))
                            except (ValueError, TypeError):
                                rateable_value = 0.0
                            
                            try:
                                rate_impost = float(row.get('rate_impost', 0.001350))
                            except (ValueError, TypeError):
                                rate_impost = 0.001350
                            
                            property = Property(
                                primary_contact=primary_contact,
                                owner_name=str(row['owner_name']).strip(),
                                house_no=str(row.get('house_no', '')).strip(),
                                email=email,
                                electoral_area=str(row['electoral_area']).strip(),
                                town=str(row['town']).strip(),
                                street_name=str(row.get('street_name', '')).strip(),
                                ghanapost_gps=str(row.get('ghanapost_gps', '')).strip(),
                                landmark=str(row.get('landmark', '')).strip(),
                                block_no=str(row['block_no']).strip(),
                                parcel_no=str(row['parcel_no']).strip(),
                                division_no=str(row['division_no']).strip(),
                                account_no=account_no,
                                category=str(row['category']).strip(),
                                property_class=str(row['property_class']).strip(),
                                zone=str(row['zone']).strip(),
                                use_code=str(row['use_code']).strip(),
                                valuation_status=str(row['valuation_status']).strip(),
                                rateable_value=rateable_value,
                                rate_impost=rate_impost,
                                created_by=current_user.id
                            )
                            
                            db.session.add(property)
                            db.session.flush()
                            
                            # Create initial invoice
                            invoice = PropertyInvoice(
                                invoice_no=generate_property_invoice_no(property.id, datetime.now().year),
                                property_id=property.id,
                                rateable_value=property.rateable_value,
                                rate_impost=property.rate_impost,
                                amount=property.rateable_value * property.rate_impost,
                                total_amount=property.rateable_value * property.rate_impost,
                                year=datetime.now().year
                            )
                            db.session.add(invoice)
                            success_count += 1
                        
                    except Exception as e:
                        processing_errors.append(f"Row {index + 2}: {str(e)}")
                        error_count += 1
                        if error_count > 50:
                            processing_errors.append("Too many errors. Upload stopped.")
                            break
            
            # Log the bulk upload action
            log_action('Bulk upload properties', 
                      details=f'Mode: {update_mode}, Created: {success_count}, Updated: {updated_count}, Skipped: {skipped_count}, Failed: {error_count}')
            
            # Build feedback messages
            messages = []
            if success_count > 0:
                messages.append(f'✅ Successfully created {success_count} new properties!')
            if updated_count > 0:
                messages.append(f'🔄 Updated {updated_count} existing properties.')
            if skipped_count > 0:
                messages.append(f'ℹ️ Skipped {skipped_count} existing properties.')
            if error_count > 0:
                messages.append(f'⚠️ {error_count} rows failed to import.')
            
            # Flash appropriate messages
            if success_count > 0 or updated_count > 0:
                flash(' '.join(messages), 'success' if error_count == 0 else 'warning')
            else:
                flash(' '.join(messages), 'info')
            
            # Show first 10 errors
            if processing_errors:
                error_details = '; '.join(processing_errors[:10])
                if len(processing_errors) > 10:
                    error_details += f' ... and {len(processing_errors) - 10} more errors'
                flash(f'Error details: {error_details}', 'error')
            
            return redirect(url_for('list_properties'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error processing file: {str(e)}', exc_info=True)
            flash(f'Error processing file: {str(e)}', 'error')
    
    return render_template('property_bulk_upload.html')

@app.route('/business/bulk-upload', methods=['GET', 'POST'])
@login_required
def bulk_upload_businesses():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        is_valid, message = validate_file_upload(file, allowed_extensions={'csv', 'xlsx'})
        
        if not is_valid:
            flash(message, 'error')
            return redirect(request.url)
        
        try:
            # Read file based on extension
            if file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            else:
                df = pd.read_excel(file)
            
            # Required columns validation
            required_columns = [
                'account_no', 'business_name', 'business_primary_contact',
                'owner_primary_contact', 'owner_name', 'electoral_area',
                'town', 'division_no', 'property_account_no',
                'category1', 'category2', 'category3', 'category4', 'category5', 'category6'
            ]
            
            missing_columns = set(required_columns) - set(df.columns)
            if missing_columns:
                flash(f'Missing required columns: {", ".join(missing_columns)}', 'error')
                return redirect(request.url)
            
            # Clean data
            df = df.fillna('')
            
            # Convert account_no to string and strip whitespace
            df['account_no'] = df['account_no'].astype(str).str.strip().str.upper()
            
            # Remove completely empty rows
            df = df[df['account_no'] != '']
            
            # Check for duplicate account numbers in the file
            duplicate_mask = df.duplicated('account_no', keep=False)
            duplicate_accounts = df[duplicate_mask]['account_no'].unique()
            
            if len(duplicate_accounts) > 0:
                duplicate_rows = []
                for acc_no in duplicate_accounts:
                    rows = df[df['account_no'] == acc_no].index.tolist()
                    duplicate_rows.append(f"{acc_no} (rows: {', '.join([str(r+2) for r in rows])})")
                
                flash(f'Duplicate account numbers in file: {"; ".join(duplicate_rows[:10])}', 'error')
                return redirect(request.url)
            
            # 🔧 NEW: Get update mode from form
            update_mode = request.form.get('update_mode', 'skip')  # 'skip', 'update', or 'fail'
            
            # Check for existing account numbers in database
            existing_businesses = BusinessOccupant.query.filter(
                BusinessOccupant.account_no.in_(df['account_no'].tolist())
            ).all()
            existing_accounts = {b.account_no: b for b in existing_businesses}
            
            # 🔧 NEW: Handle 'fail' mode
            if update_mode == 'fail' and existing_accounts:
                flash(f'❌ Strict Mode: {len(existing_accounts)} duplicate account(s) found: {", ".join(list(existing_accounts.keys())[:10])}{"..." if len(existing_accounts) > 10 else ""}', 'error')
                return redirect(request.url)
            
            # Counters
            success_count = 0        # New businesses created
            updated_count = 0        # Existing businesses updated
            skipped_count = 0        # Existing businesses skipped
            no_product_count = 0     # Created without invoice (no matching product)
            error_count = 0
            errors = []
            
            # Helper function to normalize category values
            def normalize_category(cat_value):
                """Convert NONE, empty string, None, '-', or whitespace-only to None for comparison"""
                if pd.isna(cat_value) or cat_value in ['NONE', '', None, 'N/A', '-']:
                    return None
                return str(cat_value).strip()
            
            with transaction_scope():
                for index, row in df.iterrows():
                    try:
                        account_no = str(row['account_no']).strip().upper()
                        
                        # Extract and normalize category values
                        category1 = normalize_category(row.get('category1', ''))
                        category2 = normalize_category(row.get('category2', ''))
                        category3 = normalize_category(row.get('category3', ''))
                        category4 = normalize_category(row.get('category4', ''))
                        category5 = normalize_category(row.get('category5', ''))
                        category6 = normalize_category(row.get('category6', ''))
                        
                        # Validate that at least category1 is provided
                        if not category1:
                            errors.append(f"Row {index + 2}: Category 1 is required")
                            error_count += 1
                            continue
                        
                        # Check if business exists
                        existing_business = existing_accounts.get(account_no)
                        
                        if existing_business:
                            if update_mode == 'update':
                                # 🔧 UPDATE existing business
                                existing_business.business_name = str(row['business_name']).strip()
                                existing_business.business_primary_contact = str(row['business_primary_contact']).strip()
                                existing_business.business_secondary_contact = str(row.get('business_secondary_contact', '')).strip()
                                existing_business.business_website = str(row.get('business_website', '')).strip()
                                existing_business.business_email = str(row.get('business_email', '')).strip()
                                existing_business.owner_primary_contact = str(row['owner_primary_contact']).strip()
                                existing_business.owner_name = str(row['owner_name']).strip()
                                existing_business.house_no = str(row.get('house_no', '')).strip()
                                existing_business.owner_email = str(row.get('owner_email', '')).strip()
                                existing_business.electoral_area = str(row['electoral_area']).strip()
                                existing_business.town = str(row['town']).strip()
                                existing_business.street_name = str(row.get('street_name', '')).strip()
                                existing_business.ghanapost_gps = str(row.get('ghanapost_gps', '')).strip()
                                existing_business.landmark = str(row.get('landmark', '')).strip()
                                existing_business.division_no = str(row['division_no']).strip()
                                existing_business.property_account_no = str(row['property_account_no']).strip()
                                existing_business.display_category = str(row.get('display_category', '')).strip()
                                
                                # Update categories
                                existing_business.category1 = category1 if category1 else 'NONE'
                                existing_business.category2 = category2 if category2 else 'NONE'
                                existing_business.category3 = category3 if category3 else 'NONE'
                                existing_business.category4 = category4 if category4 else 'NONE'
                                existing_business.category5 = category5 if category5 else 'NONE'
                                existing_business.category6 = category6 if category6 else 'NONE'
                                
                                updated_count += 1
                                app.logger.info(f"Updated business: {account_no}")
                                
                                # Note: Existing invoices are NOT updated automatically
                                # Consider adding logic to update/create new invoices if needed
                                
                            else:  # skip mode
                                skipped_count += 1
                                continue
                        
                        else:
                            # 🔧 CREATE new business
                            # Generate the 5-digit business ID
                            business_id = generate_business_id()
                            
                            business = BusinessOccupant(
                                business_id=business_id,
                                business_name=str(row['business_name']).strip(),
                                business_primary_contact=str(row['business_primary_contact']).strip(),
                                business_secondary_contact=str(row.get('business_secondary_contact', '')).strip(),
                                business_website=str(row.get('business_website', '')).strip(),
                                business_email=str(row.get('business_email', '')).strip(),
                                owner_primary_contact=str(row['owner_primary_contact']).strip(),
                                owner_name=str(row['owner_name']).strip(),
                                house_no=str(row.get('house_no', '')).strip(),
                                owner_email=str(row.get('owner_email', '')).strip(),
                                electoral_area=str(row['electoral_area']).strip(),
                                town=str(row['town']).strip(),
                                street_name=str(row.get('street_name', '')).strip(),
                                ghanapost_gps=str(row.get('ghanapost_gps', '')).strip(),
                                landmark=str(row.get('landmark', '')).strip(),
                                division_no=str(row['division_no']).strip(),
                                property_account_no=str(row['property_account_no']).strip(),
                                account_no=account_no,
                                display_category=str(row.get('display_category', '')).strip(),
                                category1=category1 if category1 else 'NONE',
                                category2=category2 if category2 else 'NONE',
                                category3=category3 if category3 else 'NONE',
                                category4=category4 if category4 else 'NONE',
                                category5=category5 if category5 else 'NONE',
                                category6=category6 if category6 else 'NONE',
                                created_by=current_user.id
                            )
                            
                            db.session.add(business)
                            db.session.flush()  # Get the business.id
                            
                            # Try to find matching product for invoice
                            filters = []
                            
                            # Category 1 must match
                            if category1 is None:
                                filters.append(Product.category1.is_(None))
                            else:
                                filters.append(Product.category1 == category1)
                            
                            # Categories 2-6: match both explicit values and NULL
                            for i in range(2, 7):
                                cat_value = locals()[f'category{i}']
                                col = getattr(Product, f'category{i}')
                                
                                if cat_value is None:
                                    filters.append(col.is_(None))
                                else:
                                    filters.append(col == cat_value)
                            
                            # Find matching product
                            product = Product.query.filter(*filters).first()
                            
                            if product:
                                # Create rate key from categories (for display)
                                rate_key_parts = [category1, category2, category3, category4, category5, category6]
                                rate_key = '-'.join([str(p) if p else 'N/A' for p in rate_key_parts])
                                
                                # Generate invoice with format: INVNBOP-{business_id}-{year}
                                invoice = BOPInvoice(
                                    invoice_no=generate_business_invoice_no(business.business_id, datetime.now().year),
                                    business_id=business.id,
                                    product_name=rate_key,
                                    amount=product.amount,
                                    year=datetime.now().year,
                                    status='Unpaid'
                                )
                                db.session.add(invoice)
                            else:
                                # Business created but no invoice due to missing product
                                no_product_count += 1
                                search_details = f"cat1={category1}, cat2={category2}, cat3={category3}, cat4={category4}, cat5={category5}, cat6={category6}"
                                app.logger.warning(f"Row {index + 2}: No matching product found. Search: [{search_details}]. Business created without invoice.")
                            
                            success_count += 1
                        
                    except Exception as e:
                        errors.append(f"Row {index + 2}: {str(e)}")
                        error_count += 1
                        if error_count > 50:  # Limit error reporting
                            errors.append("Too many errors. Upload stopped.")
                            break
            
            # Log the bulk upload action
            log_action('Bulk upload businesses', 
                      details=f'Mode: {update_mode}, Created: {success_count}, Updated: {updated_count}, Skipped: {skipped_count}, No Product: {no_product_count}, Failed: {error_count}')
            
            # Build feedback messages
            messages = []
            if success_count > 0:
                messages.append(f'✅ Successfully created {success_count} new businesses!')
            if updated_count > 0:
                messages.append(f'🔄 Updated {updated_count} existing businesses.')
            if skipped_count > 0:
                messages.append(f'ℹ️ Skipped {skipped_count} existing businesses.')
            if no_product_count > 0:
                messages.append(f'⚠️ {no_product_count} businesses created without invoices (no matching products found).')
            if error_count > 0:
                messages.append(f'❌ {error_count} rows failed.')
            
            # Flash appropriate messages
            if success_count > 0 or updated_count > 0:
                flash(' '.join(messages), 'success' if error_count == 0 else 'warning')
            else:
                flash(' '.join(messages), 'info' if skipped_count > 0 else 'error')
            
            # Show first 10 errors if any
            if errors:
                error_details = '; '.join(errors[:10])
                if len(errors) > 10:
                    error_details += f' ... and {len(errors) - 10} more errors'
                flash(f'Error details: {error_details}', 'error')
            
            return redirect(url_for('list_businesses'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error processing file: {str(e)}', exc_info=True)
            flash(f'Error processing file: {str(e)}', 'error')
    
    return render_template('business_bulk_upload.html')

@app.route('/product/bulk-upload', methods=['GET', 'POST'])
@login_required
def bulk_upload_products():
    """Bulk upload products - checks ALL fields except product_name for existence"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        is_valid, message = validate_file_upload(file, allowed_extensions={'csv', 'xlsx'})
        
        if not is_valid:
            flash(message, 'error')
            return redirect(request.url)
        
        try:
            # Read file
            if file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            else:
                df = pd.read_excel(file)
            
            # Required columns
            required_columns = ['product_name', 'amount']
            missing_columns = set(required_columns) - set(df.columns)
            if missing_columns:
                flash(f'Missing required columns: {", ".join(missing_columns)}', 'error')
                return redirect(request.url)
            
            # Clean data
            df = df.fillna('')
            
            # Define update strategy
            update_mode = request.form.get('update_mode', 'skip')  # 'skip', 'update', or 'create_only'
            
            success_count = 0
            updated_count = 0
            skipped_count = 0
            error_count = 0
            errors = []
            
            # Helper function to normalize category values
            def normalize_category(cat_value):
                """Convert empty, None, 'N/A', '-', or whitespace to None"""
                if pd.isna(cat_value) or cat_value in ['', 'N/A', '-', 'NONE']:
                    return None
                return str(cat_value).strip()
            
            # 🆕 NEW: Function to find product by ALL fields except product_name
            def find_product_by_all_fields(cat1, cat2, cat3, cat4, cat5, cat6, amount, rate_impost):
                """Find product matching categories 1-6, amount, AND rate_impost"""
                query = Product.query
                
                # Build filters for each category
                for i, cat_value in enumerate([cat1, cat2, cat3, cat4, cat5, cat6], 1):
                    col = getattr(Product, f'category{i}')
                    
                    if cat_value is None:
                        query = query.filter(col.is_(None))
                    else:
                        query = query.filter(col == cat_value)
                
                # 🆕 ADD: Also match amount and rate_impost
                query = query.filter(Product.amount == amount)
                query = query.filter(Product.rate_impost == rate_impost)
                
                return query.first()
            
            # Track existing products by complete field signature
            existing_products_cache = {}
            
            with transaction_scope():
                for index, row in df.iterrows():
                    try:
                        # Extract and normalize categories
                        category1 = normalize_category(row.get('category1', ''))
                        category2 = normalize_category(row.get('category2', ''))
                        category3 = normalize_category(row.get('category3', ''))
                        category4 = normalize_category(row.get('category4', ''))
                        category5 = normalize_category(row.get('category5', ''))
                        category6 = normalize_category(row.get('category6', ''))
                        
                        # Extract other fields
                        product_name = str(row['product_name']).strip()
                        
                        try:
                            amount = float(row['amount'])
                        except (ValueError, TypeError):
                            errors.append(f"Row {index + 2}: Invalid amount value")
                            error_count += 1
                            continue
                        
                        try:
                            rate_impost = float(row.get('rate_impost', 0.001350))
                        except (ValueError, TypeError):
                            rate_impost = 0.001350
                        
                        # 🆕 CHANGED: Create cache key from ALL fields except product_name
                        cache_key = f"{category1}|{category2}|{category3}|{category4}|{category5}|{category6}|{amount}|{rate_impost}"
                        
                        # Check if product exists by ALL fields (except product_name)
                        if cache_key in existing_products_cache:
                            existing_product = existing_products_cache[cache_key]
                        else:
                            existing_product = find_product_by_all_fields(
                                category1, category2, category3, category4, category5, category6,
                                amount, rate_impost
                            )
                            existing_products_cache[cache_key] = existing_product
                        
                        if existing_product:
                            if update_mode == 'update':
                                # UPDATE: Only update product_name (all other fields match)
                                existing_product.product_name = product_name
                                
                                updated_count += 1
                                app.logger.info(f"Updated product name: {existing_product.product_name} → {product_name}")
                                
                            elif update_mode == 'create_only':
                                # FAIL mode: Product with these exact fields already exists
                                errors.append(f"Row {index + 2}: Product with matching fields already exists (Name: {existing_product.product_name})")
                                error_count += 1
                                continue
                                
                            else:  # skip mode
                                skipped_count += 1
                                continue
                        
                        else:
                            # CREATE new product (no match found)
                            product = Product(
                                product_name=product_name,
                                category1=category1,
                                category2=category2,
                                category3=category3,
                                category4=category4,
                                category5=category5,
                                category6=category6,
                                amount=amount,
                                rate_impost=rate_impost
                            )
                            
                            db.session.add(product)
                            success_count += 1
                        
                    except ValueError as ve:
                        errors.append(f"Row {index + 2}: Invalid amount - {str(ve)}")
                        error_count += 1
                    except Exception as e:
                        errors.append(f"Row {index + 2}: {str(e)}")
                        error_count += 1
                        
                    # Stop if too many errors
                    if error_count > 50:
                        errors.append("Too many errors. Upload stopped.")
                        break
            
            # Log the action
            log_action('Bulk upload products', 
                      details=f'Mode: {update_mode}, Created: {success_count}, Updated: {updated_count}, Skipped: {skipped_count}, Failed: {error_count}')
            
            # Build feedback messages
            messages = []
            if success_count > 0:
                messages.append(f'✅ Successfully imported {success_count} new products!')
            if updated_count > 0:
                messages.append(f'🔄 Updated {updated_count} product names (all other fields matched).')
            if skipped_count > 0:
                messages.append(f'ℹ️ Skipped {skipped_count} existing products (all fields matched).')
            if error_count > 0:
                messages.append(f'⚠️ {error_count} rows failed.')
            
            # Flash appropriate message type
            if success_count > 0 or updated_count > 0:
                flash(' '.join(messages), 'success' if error_count == 0 else 'warning')
            else:
                flash(' '.join(messages), 'error')
            
            # Show first 10 errors
            if errors:
                error_details = '; '.join(errors[:10])
                if len(errors) > 10:
                    error_details += f' ... and {len(errors) - 10} more errors'
                flash(f'Error details: {error_details}', 'error')
            
            return redirect(url_for('list_products'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error processing file: {str(e)}')
            flash(f'Error processing file: {str(e)}', 'error')
    
    return render_template('product_bulk_upload.html')
# ==================== API Routes ====================
@app.route('/api/products')
@login_required
def api_products():
    products = Product.query.all()
    return jsonify([{
        'id': p.id,
        'product_name': p.product_name,
        'amount': p.amount,
        'category1': p.category1,
        'category2': p.category2,
        'category3': p.category3,
        'category4': p.category4,
        'category5': p.category5,
        'category6': p.category6
    } for p in products])

@app.route('/api/product-categories')
@login_required
def api_product_categories():
    products = Product.query.all()
    
    categories = {
        'category1': set(),
        'category2': set(),
        'category3': set(),
        'category4': set(),
        'category5': set(),
        'category6': set()
    }
    
    for product in products:
        if product.category1 and product.category1.strip():
            categories['category1'].add(product.category1.strip())
        if product.category2 and product.category2.strip():
            categories['category2'].add(product.category2.strip())
        if product.category3 and product.category3.strip():
            categories['category3'].add(product.category3.strip())
        if product.category4 and product.category4.strip():
            categories['category4'].add(product.category4.strip())
        if product.category5 and product.category5.strip():
            categories['category5'].add(product.category5.strip())
        if product.category6 and product.category6.strip():
            categories['category6'].add(product.category6.strip())
    
    return jsonify({
        'category1': sorted(list(categories['category1'])),
        'category2': sorted(list(categories['category2'])),
        'category3': sorted(list(categories['category3'])),
        'category4': sorted(list(categories['category4'])),
        'category5': sorted(list(categories['category5'])),
        'category6': sorted(list(categories['category6']))
    })

@app.route('/api/search/properties')
@login_required
def api_search_properties():
    search_term = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = Property.query
    
    if search_term:
        query = query.filter(
            db.or_(
                Property.account_no.ilike(f'%{search_term}%'),
                Property.owner_name.ilike(f'%{search_term}%'),
                Property.electoral_area.ilike(f'%{search_term}%')
            )
        )
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'properties': [{
            'id': p.id,
            'account_no': p.account_no,
            'owner_name': p.owner_name,
            'electoral_area': p.electoral_area,
            'town': p.town,
            'rateable_value': p.rateable_value
        } for p in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })

@app.route('/api/search/businesses')
@login_required
def api_search_businesses():
    search_term = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = BusinessOccupant.query
    
    if search_term:
        query = query.filter(
            db.or_(
                BusinessOccupant.account_no.ilike(f'%{search_term}%'),
                BusinessOccupant.business_name.ilike(f'%{search_term}%'),
                BusinessOccupant.owner_name.ilike(f'%{search_term}%')
            )
        )
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'businesses': [{
            'id': b.id,
            'account_no': b.account_no,
            'business_name': b.business_name,
            'owner_name': b.owner_name,
            'electoral_area': b.electoral_area
        } for b in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })

@app.route('/api/statistics')
@login_required
def api_statistics():
    """API endpoint for dashboard statistics"""
    current_year = datetime.now().year
    
    stats = {
        'total_properties': Property.query.count(),
        'total_businesses': BusinessOccupant.query.count(),
        'total_products': Product.query.count(),
        'property_invoices': {
            'total': PropertyInvoice.query.filter_by(year=current_year).count(),
            'paid': PropertyInvoice.query.filter_by(year=current_year, status='Paid').count(),
            'unpaid': PropertyInvoice.query.filter_by(year=current_year, status='Unpaid').count(),
            'partially_paid': PropertyInvoice.query.filter_by(year=current_year, status='Partially Paid').count()
        },
        'business_invoices': {
            'total': BOPInvoice.query.filter_by(year=current_year).count(),
            'paid': BOPInvoice.query.filter_by(year=current_year, status='Paid').count(),
            'unpaid': BOPInvoice.query.filter_by(year=current_year, status='Unpaid').count(),
            'partially_paid': BOPInvoice.query.filter_by(year=current_year, status='Partially Paid').count()
        },
        'revenue': {
            'total': db.session.query(db.func.sum(Payment.payment_amount)).scalar() or 0,
            'current_year': db.session.query(db.func.sum(Payment.payment_amount)).filter(
                db.extract('year', Payment.payment_date) == current_year
            ).scalar() or 0,
            'current_month': db.session.query(db.func.sum(Payment.payment_amount)).filter(
                db.extract('year', Payment.payment_date) == current_year,
                db.extract('month', Payment.payment_date) == datetime.now().month
            ).scalar() or 0
        }
    }
    
    return jsonify(stats)

# ==================== Template Download Routes ====================
@app.route('/download/property-template')
@login_required
def download_property_template():
    data = {
        'primary_contact': ['0241234567'],
        'owner_name': ['John Doe'],
        'house_no': ['10'],
        'email': ['john@example.com'],
        'electoral_area': ['LEGON'],
        'town': ['Accra'],
        'street_name': ['Oxford Street'],
        'ghanapost_gps': ['GA-377-6899'],
        'landmark': ['Near University'],
        'block_no': ['9'],
        'parcel_no': ['21'],
        'division_no': ['11'],
        'account_no': ['AYWMA141001'],
        'category': ['Commercial'],
        'property_class': ['Class 1'],
        'zone': ['FIRST CLASS A'],
        'use_code': ['Mixed'],
        'valuation_status': ['Valued'],
        'rateable_value': [370254.00],
        'rate_impost': [0.001350]
    }
    
    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='property_template.csv'
    )

@app.route('/download/business-template')
@login_required
def download_business_template():
    data = {
        'business_name': ['ABC Restaurant'],
        'business_primary_contact': ['0241234567'],
        'business_secondary_contact': ['0202345678'],
        'business_website': ['https://abc-restaurant.com'],
        'business_email': ['info@abc-restaurant.com'],
        'owner_primary_contact': ['0241234567'],
        'owner_name': ['Jane Smith'],
        'house_no': ['15'],
        'owner_email': ['jane@example.com'],
        'electoral_area': ['LEGON'],
        'town': ['Accra'],
        'street_name': ['Main Street'],
        'ghanapost_gps': ['GA-123-4567'],
        'landmark': ['Near Market'],
        'division_no': ['11'],
        'property_account_no': ['AYWMA141001'],
        'account_no': ['BOP001'],
        'display_category': ['A'],
        'category1': ['Food Service'],
        'category2': ['Small Scale'],
        'category3': [''],
        'category4': [''],
        'category5': [''],
        'category6': ['']
    }
    
    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='business_template.csv'
    )

@app.route('/download/product-template')
@login_required
def download_product_template():
    data = {
        'product_name': ['Restaurant License - Small', 'Retail Shop License'],
        'category1': ['Food Service', 'Retail'],
        'category2': ['Small Scale', 'Small Scale'],
        'category3': ['Indoor', 'Indoor'],
        'category4': ['', ''],
        'category5': ['', ''],
        'category6': ['', ''],
        'amount': [500.00, 300.00]
    }
    
    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='product_template.csv'
    )

# ==================== Export Routes ====================
@app.route('/export/properties')
@login_required
def export_properties():
    """Export all properties to CSV"""
    properties = Property.query.all()
    
    data = []
    for p in properties:
        data.append({
            'account_no': p.account_no,
            'owner_name': p.owner_name,
            'primary_contact': p.primary_contact,
            'email': p.email,
            'house_no': p.house_no,
            'electoral_area': p.electoral_area,
            'town': p.town,
            'street_name': p.street_name,
            'ghanapost_gps': p.ghanapost_gps,
            'landmark': p.landmark,
            'block_no': p.block_no,
            'parcel_no': p.parcel_no,
            'division_no': p.division_no,
            'category': p.category,
            'property_class': p.property_class,
            'zone': p.zone,
            'use_code': p.use_code,
            'valuation_status': p.valuation_status,
            'rateable_value': p.rateable_value,
            'rate_impost': p.rate_impost,
            'created_at': p.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    log_action('Export properties', details=f'{len(properties)} properties exported')
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'properties_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/export/businesses')
@login_required
def export_businesses():
    """Export all businesses to CSV"""
    businesses = BusinessOccupant.query.all()
    
    data = []
    for b in businesses:
        data.append({
            'account_no': b.account_no,
            'business_name': b.business_name,
            'business_primary_contact': b.business_primary_contact,
            'business_secondary_contact': b.business_secondary_contact,
            'business_email': b.business_email,
            'business_website': b.business_website,
            'owner_name': b.owner_name,
            'owner_primary_contact': b.owner_primary_contact,
            'owner_email': b.owner_email,
            'electoral_area': b.electoral_area,
            'town': b.town,
            'street_name': b.street_name,
            'display_category': b.display_category,
            'created_at': b.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    log_action('Export businesses', details=f'{len(businesses)} businesses exported')
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'businesses_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/export/payments')
@login_required
def export_payments():
    """Export all payments to CSV"""
    payments = Payment.query.all()
    
    data = []
    for p in payments:
        data.append({
            'invoice_no': p.invoice_no,
            'invoice_type': p.invoice_type,
            'payment_mode': p.payment_mode,
            'payment_type': p.payment_type,
            'payment_amount': p.payment_amount,
            'paid_by': p.paid_by,
            'payer_name': p.payer_name,
            'payer_phone': p.payer_phone,
            'payment_date': p.payment_date.strftime('%Y-%m-%d %H:%M:%S'),
            'status': p.status,
            'created_by': p.created_by
        })
    
    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    log_action('Export payments', details=f'{len(payments)} payments exported')
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'payments_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/export/products')
@login_required
def export_products():
    """Export all products to CSV"""
    products = Product.query.all()

    data = []
    for p in products:
        data.append({
            'product_name': p.product_name,
            'category1': p.category1,
            'category2': p.category2,
            'category3': p.category3,
            'category4': p.category4,
            'category5': p.category5,
            'category6': p.category6,
            'amount': p.amount,
            'created_at': p.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })

    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)

    log_action('Export products', details=f'{len(products)} products exported')

    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'products_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

# ==================== Admin Routes ====================
@app.route('/admin/audit-logs')
@login_required
def audit_logs():
    """View audit logs (admin only)"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=app.config['ITEMS_PER_PAGE'], error_out=False
    )
    
    return render_template('admin/audit_logs.html', logs=logs)

@app.route('/admin/backup-database')
@login_required
def admin_backup_database():
    """Create database backup (admin only)"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    try:
        backup_path = backup_database()
        if backup_path:
            log_action('Database backup created', details=backup_path)
            flash(f'Database backup created successfully: {backup_path}', 'success')
        else:
            flash('Database backup failed', 'error')
    except Exception as e:
        app.logger.error(f'Backup error: {str(e)}')
        flash(f'Error creating backup: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/admin/users')
@login_required
def admin_users():
    """Manage users (admin only)"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>/toggle-role', methods=['POST'])
@login_required
def toggle_user_role(user_id):
    """Toggle user role between admin and user"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Cannot modify your own role', 'error')
        return redirect(url_for('admin_users'))
    
    user.role = 'admin' if user.role == 'user' else 'user'
    db.session.commit()
    
    log_action('User role changed', 'User', user_id, f'New role: {user.role}')
    flash(f'User role updated to {user.role}', 'success')
    
    return redirect(url_for('admin_users'))

# Replace the FIRST create_user function (around line 1358) with this:

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    """Create new user with temporary password - Admin only"""
    if current_user.role != 'admin': 
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        phone_number = request.form.get('phone_number')
        
        # Validate all required fields
        if not username or not email or not role or not phone_number:
            flash('All fields are required.', 'error')
            return render_template('admin/create_user.html')
            
        # Check for existing username
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('admin/create_user.html')
        
        # Check for existing email
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('admin/create_user.html')

        # Generate temporary password
        temp_password = generate_temp_password()
        
        # Create new user
        user = User(
            username=username, 
            email=email, 
            role=role, 
            phone_number=phone_number,
            is_temp_password=True
        )
        user.set_password(temp_password)
        
        db.session.add(user)
        db.session.flush()  # Get user.id
        
        # 🔒 STORE TEMPORARY PASSWORD
        temp_password_record = TemporaryPassword(
            user_id=user.id,
            temp_password=temp_password,  # Store plain text for admin to view
            expires_at=datetime.utcnow() + timedelta(days=7),  # Expires in 7 days
            created_by=current_user.id
        )
        db.session.add(temp_password_record)
        db.session.commit()
        
        log_action('User created with temp password', 'User', user.id, f'Role: {role}')
        
        # Show temporary password to admin
        flash(f'User created successfully! <br><strong>Temporary Password:</strong> <code>{temp_password}</code><br>⚠️ The user must reset their password on first login. Please share this password securely.<br><em>Password stored in system for 7 days.</em>', 'success')
        
        return redirect(url_for('admin_users'))

    return render_template('admin/create_user.html')

# Add this route to your app.py (place it with other admin user management routes)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete a user - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin_users'))
    
    # Store username before deletion for logging
    username = user.username
    
    try:
        db.session.delete(user)
        db.session.commit()
        
        log_action('User deleted', 'User', user_id, f'Username: {username}')
        flash(f'User "{username}" deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting user: {str(e)}')
        flash(f'Error deleting user: {str(e)}', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/temp-passwords')
@login_required
def view_temp_passwords():
    """View all temporary passwords - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    page = request.args.get('page', 1, type=int)
    
    # Get all temp passwords, newest first - FIX: Remove the join, just order by created_at
    pagination = TemporaryPassword.query.order_by(
        TemporaryPassword.created_at.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    
    return render_template('admin/temp_passwords.html', pagination=pagination)


# Add route to cleanup expired temporary passwords

@app.route('/admin/temp-passwords/cleanup', methods=['POST'])
@login_required
def cleanup_temp_passwords():
    """Delete expired and used temporary passwords - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Delete passwords that are expired or used
        deleted = TemporaryPassword.query.filter(
            db.or_(
                TemporaryPassword.expires_at < datetime.utcnow(),
                TemporaryPassword.used == True
            )
        ).delete()
        
        db.session.commit()
        
        log_action('Temporary passwords cleaned up', details=f'{deleted} passwords deleted')
        flash(f'Successfully cleaned up {deleted} temporary passwords', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error cleaning up temp passwords: {str(e)}')
        flash('Error cleaning up temporary passwords', 'error')
    
    return redirect(url_for('view_temp_passwords'))

# ==================== Database Cleanup & Integrity Routes ====================

@app.route('/admin/database/integrity-check')
@login_required
def database_integrity_check():
    """Check database integrity and find orphaned records (Admin only)"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    issues = {
        'orphaned_property_invoices': [],
        'orphaned_business_invoices': [],
        'orphaned_payments': [],
        'orphaned_adjustments': [],
        'missing_products': [],
        'total_issues': 0
    }
    
    # Check for orphaned property invoices
    orphaned_prop_invoices = PropertyInvoice.query.filter(
        ~PropertyInvoice.property_id.in_(
            db.session.query(Property.id)
        )
    ).all()
    
    for invoice in orphaned_prop_invoices:
        issues['orphaned_property_invoices'].append({
            'id': invoice.id,
            'invoice_no': invoice.invoice_no,
            'property_id': invoice.property_id
        })
    
    # Check for orphaned business invoices
    orphaned_biz_invoices = BOPInvoice.query.filter(
        ~BOPInvoice.business_id.in_(
            db.session.query(BusinessOccupant.id)
        )
    ).all()
    
    for invoice in orphaned_biz_invoices:
        issues['orphaned_business_invoices'].append({
            'id': invoice.id,
            'invoice_no': invoice.invoice_no,
            'business_id': invoice.business_id
        })
    
    # Check for orphaned payments (property)
    orphaned_prop_payments = Payment.query.filter(
        Payment.property_invoice_id.isnot(None),
        ~Payment.property_invoice_id.in_(
            db.session.query(PropertyInvoice.id)
        )
    ).all()
    
    for payment in orphaned_prop_payments:
        issues['orphaned_payments'].append({
            'id': payment.id,
            'invoice_no': payment.invoice_no,
            'type': 'Property',
            'amount': payment.payment_amount
        })
    
    # Check for orphaned payments (business)
    orphaned_biz_payments = Payment.query.filter(
        Payment.business_invoice_id.isnot(None),
        ~Payment.business_invoice_id.in_(
            db.session.query(BOPInvoice.id)
        )
    ).all()
    
    for payment in orphaned_biz_payments:
        issues['orphaned_payments'].append({
            'id': payment.id,
            'invoice_no': payment.invoice_no,
            'type': 'Business',
            'amount': payment.payment_amount
        })
    
    # Check for orphaned adjustments (property)
    orphaned_prop_adjustments = InvoiceAdjustment.query.filter(
        InvoiceAdjustment.property_invoice_id.isnot(None),
        ~InvoiceAdjustment.property_invoice_id.in_(
            db.session.query(PropertyInvoice.id)
        )
    ).all()
    
    for adj in orphaned_prop_adjustments:
        issues['orphaned_adjustments'].append({
            'id': adj.id,
            'invoice_no': adj.invoice_no,
            'type': 'Property',
            'adjustment_type': adj.adjustment_type
        })
    
    # Check for orphaned adjustments (business)
    orphaned_biz_adjustments = InvoiceAdjustment.query.filter(
        InvoiceAdjustment.business_invoice_id.isnot(None),
        ~InvoiceAdjustment.business_invoice_id.in_(
            db.session.query(BOPInvoice.id)
        )
    ).all()
    
    for adj in orphaned_biz_adjustments:
        issues['orphaned_adjustments'].append({
            'id': adj.id,
            'invoice_no': adj.invoice_no,
            'type': 'Business',
            'adjustment_type': adj.adjustment_type
        })
    
    # Check for missing products referenced in BOP invoices
    all_bop_products = db.session.query(BOPInvoice.product_name).distinct().all()
    all_products = db.session.query(Product.product_name).all()
    product_names = {p[0] for p in all_products}
    
    for prod_name in all_bop_products:
        if prod_name[0] and prod_name[0] not in product_names:
            # Count how many invoices reference this missing product
            count = BOPInvoice.query.filter_by(product_name=prod_name[0]).count()
            issues['missing_products'].append({
                'product_name': prod_name[0],
                'invoice_count': count
            })
    
    # Calculate total issues
    issues['total_issues'] = (
        len(issues['orphaned_property_invoices']) +
        len(issues['orphaned_business_invoices']) +
        len(issues['orphaned_payments']) +
        len(issues['orphaned_adjustments']) +
        len(issues['missing_products'])
    )
    
    return render_template('admin/database_integrity.html', issues=issues)


@app.route('/admin/database/cleanup', methods=['POST'])
@login_required
def database_cleanup():
    """Clean up orphaned records (Admin only)"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    try:
        cleanup_stats = {
            'invoices_deleted': 0,
            'payments_deleted': 0,
            'adjustments_deleted': 0
        }
        
        # Delete orphaned property invoices
        orphaned_prop_invoices = PropertyInvoice.query.filter(
            ~PropertyInvoice.property_id.in_(
                db.session.query(Property.id)
            )
        ).all()
        
        for invoice in orphaned_prop_invoices:
            db.session.delete(invoice)
            cleanup_stats['invoices_deleted'] += 1
        
        # Delete orphaned business invoices
        orphaned_biz_invoices = BOPInvoice.query.filter(
            ~BOPInvoice.business_id.in_(
                db.session.query(BusinessOccupant.id)
            )
        ).all()
        
        for invoice in orphaned_biz_invoices:
            db.session.delete(invoice)
            cleanup_stats['invoices_deleted'] += 1
        
        # Delete orphaned payments (property)
        orphaned_prop_payments = Payment.query.filter(
            Payment.property_invoice_id.isnot(None),
            ~Payment.property_invoice_id.in_(
                db.session.query(PropertyInvoice.id)
            )
        ).all()
        
        for payment in orphaned_prop_payments:
            db.session.delete(payment)
            cleanup_stats['payments_deleted'] += 1
        
        # Delete orphaned payments (business)
        orphaned_biz_payments = Payment.query.filter(
            Payment.business_invoice_id.isnot(None),
            ~Payment.business_invoice_id.in_(
                db.session.query(BOPInvoice.id)
            )
        ).all()
        
        for payment in orphaned_biz_payments:
            db.session.delete(payment)
            cleanup_stats['payments_deleted'] += 1
        
        # Delete orphaned adjustments (property)
        orphaned_prop_adjustments = InvoiceAdjustment.query.filter(
            InvoiceAdjustment.property_invoice_id.isnot(None),
            ~InvoiceAdjustment.property_invoice_id.in_(
                db.session.query(PropertyInvoice.id)
            )
        ).all()
        
        for adj in orphaned_prop_adjustments:
            db.session.delete(adj)
            cleanup_stats['adjustments_deleted'] += 1
        
        # Delete orphaned adjustments (business)
        orphaned_biz_adjustments = InvoiceAdjustment.query.filter(
            InvoiceAdjustment.business_invoice_id.isnot(None),
            ~InvoiceAdjustment.business_invoice_id.in_(
                db.session.query(BOPInvoice.id)
            )
        ).all()
        
        for adj in orphaned_biz_adjustments:
            db.session.delete(adj)
            cleanup_stats['adjustments_deleted'] += 1
        
        db.session.commit()
        
        log_action('Database cleanup performed', 
                  details=f"Deleted {cleanup_stats['invoices_deleted']} invoices, "
                         f"{cleanup_stats['payments_deleted']} payments, "
                         f"{cleanup_stats['adjustments_deleted']} adjustments")
        
        flash(f"✅ Cleanup complete! Removed {cleanup_stats['invoices_deleted']} orphaned invoices, "
              f"{cleanup_stats['payments_deleted']} orphaned payments, and "
              f"{cleanup_stats['adjustments_deleted']} orphaned adjustments.", 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Database cleanup error: {str(e)}')
        flash(f'Error during cleanup: {str(e)}', 'error')
    
    return redirect(url_for('database_integrity_check'))


@app.route('/admin/database/reset-sequences', methods=['POST'])
@login_required
def reset_sequences():
    """Reset database sequences/auto-increment (Admin only)"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Detect database type
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        
        if 'postgresql' in db_uri:
            # PostgreSQL sequence reset
            db.session.execute(db.text("SELECT setval('property_id_seq', (SELECT MAX(id) FROM property))"))
            db.session.execute(db.text("SELECT setval('business_occupant_id_seq', (SELECT MAX(id) FROM business_occupant))"))
            db.session.execute(db.text("SELECT setval('product_id_seq', (SELECT MAX(id) FROM product))"))
            db.session.commit()
            
            flash('✅ PostgreSQL sequences reset successfully!', 'success')
            log_action('Database sequences reset (PostgreSQL)')
            
        elif 'sqlite' in db_uri:
            # SQLite sequence reset (existing code)
            max_property_id = db.session.query(db.func.max(Property.id)).scalar() or 0
            db.session.execute(
                db.text(f"UPDATE sqlite_sequence SET seq = {max_property_id} WHERE name = 'property'")
            )
            
            max_business_id = db.session.query(db.func.max(BusinessOccupant.id)).scalar() or 0
            db.session.execute(
                db.text(f"UPDATE sqlite_sequence SET seq = {max_business_id} WHERE name = 'business_occupant'")
            )
            
            max_product_id = db.session.query(db.func.max(Product.id)).scalar() or 0
            db.session.execute(
                db.text(f"UPDATE sqlite_sequence SET seq = {max_product_id} WHERE name = 'product'")
            )
            
            db.session.commit()
            
            flash('✅ SQLite sequences reset successfully!', 'success')
            log_action('Database sequences reset (SQLite)')
        else:
            flash('Sequence reset only supported for PostgreSQL and SQLite', 'warning')
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Sequence reset error: {str(e)}')
        flash(f'Error resetting sequences: {str(e)}', 'error')
    
    return redirect(url_for('database_integrity_check'))

# ==================== OTP Admin/Management Routes ====================

@app.route('/admin/otp-logs')
@login_required
def otp_logs():
    """View OTP verification logs - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    page = request.args.get('page', 1, type=int)
    
    # Get all OTP records, newest first
    pagination = OTPVerification.query.order_by(
        OTPVerification.created_at.desc()
    ).paginate(page=page, per_page=50, error_out=False)
    
    return render_template('admin/otp_logs.html', pagination=pagination)


# ==================== System Health & Monitoring ====================
@app.route('/health')
def health_check():
    """System health check endpoint"""
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'checks': {}
    }
    
    # Check database connection
    try:
        db.session.execute('SELECT 1')
        health_status['checks']['database'] = 'connected'
    except Exception as e:
        health_status['status'] = 'unhealthy'
        health_status['checks']['database'] = f'error: {str(e)}'
    
    # Check disk space (for uploads and backups)
    try:
        import shutil
        upload_disk = shutil.disk_usage(app.config['UPLOAD_FOLDER'])
        health_status['checks']['disk_space'] = {
            'total': f'{upload_disk.total / (1024**3):.2f} GB',
            'used': f'{upload_disk.used / (1024**3):.2f} GB',
            'free': f'{upload_disk.free / (1024**3):.2f} GB',
            'percent_used': f'{(upload_disk.used / upload_disk.total) * 100:.1f}%'
        }
    except Exception as e:
        health_status['checks']['disk_space'] = f'error: {str(e)}'
    
    # Check required directories exist
    required_dirs = [
        app.config['UPLOAD_FOLDER'],
        'logs',
        'backups'
    ]
    
    missing_dirs = [d for d in required_dirs if not os.path.exists(d)]
    if missing_dirs:
        health_status['status'] = 'degraded'
        health_status['checks']['directories'] = f'missing: {", ".join(missing_dirs)}'
    else:
        health_status['checks']['directories'] = 'ok'
    
    # Return appropriate status code
    status_code = 200 if health_status['status'] == 'healthy' else 503
    
    return jsonify(health_status), status_code

@app.route('/metrics')
@login_required
def system_metrics():
    """System metrics endpoint (admin only)"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    metrics = {
        'database': {
            'properties': Property.query.count(),
            'businesses': BusinessOccupant.query.count(),
            'products': Product.query.count(),
            'users': User.query.count(),
            'property_invoices': PropertyInvoice.query.count(),
            'business_invoices': BOPInvoice.query.count(),
            'payments': Payment.query.count(),
            'audit_logs': AuditLog.query.count()
        },
        'storage': {
            'upload_folder': app.config['UPLOAD_FOLDER'],
            'file_count': len(os.listdir(app.config['UPLOAD_FOLDER'])) if os.path.exists(app.config['UPLOAD_FOLDER']) else 0
        },
        'system': {
            'python_version': sys.version,
            'flask_version': flask.__version__
        }
    }
    
    return jsonify(metrics)

# ==================== Batch Invoice Generation Routes ====================

@app.route('/batch-invoice/generate', methods=['GET'])
@login_required
def batch_invoice_page():
    """Batch invoice generation page"""
    return render_template('batch_invoice_generate.html')


@app.route('/api/batch-invoice/filters', methods=['GET'])
@login_required
def get_batch_invoice_filters():
    """Get filter options for batch generation"""
    try:
        # Get unique electoral areas
        electoral_areas = db.session.query(Property.electoral_area).distinct().all()
        electoral_areas += db.session.query(BusinessOccupant.electoral_area).distinct().all()
        electoral_areas = sorted(list(set([e[0] for e in electoral_areas if e[0]])))
        
        # Get unique towns
        towns = db.session.query(Property.town).distinct().all()
        towns += db.session.query(BusinessOccupant.town).distinct().all()
        towns = sorted(list(set([t[0] for t in towns if t[0]])))
        
        return jsonify({
            'success': True,
            'electoral_areas': electoral_areas,
            'towns': towns
        })
    except Exception as e:
        app.logger.error(f'Error fetching filters: {str(e)}')
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/api/batch-invoice/preview', methods=['POST'])
@login_required
def batch_invoice_preview():
    """Preview records that will have invoices generated"""
    try:
        data = request.get_json()
        
        year = int(data.get('year'))
        bill_type = data.get('billType')
        run_type = data.get('runType')
        amount_type = data.get('amountType')
        fixed_amount = float(data.get('fixedAmount', 0)) if data.get('fixedAmount') else None
        electoral_area = data.get('electoralArea')
        town = data.get('town')
        
        records = []
        property_count = 0
        business_count = 0
        total_amount = 0.0
        
        # Get properties
        if bill_type in ['all', 'property']:
            query = Property.query
            
            # Apply filters
            if electoral_area != 'all':
                query = query.filter_by(electoral_area=electoral_area)
            if town != 'all':
                query = query.filter_by(town=town)
            
            properties = query.all()
            
            for prop in properties:
                # Check if invoice already exists
                existing_invoice = PropertyInvoice.query.filter_by(
                    property_id=prop.id,
                    year=year
                ).first()
                
                # Skip if normal run and invoice exists
                if run_type == 'normal' and existing_invoice:
                    continue
                
                # Calculate amount
                if amount_type == 'fixed_amount' and fixed_amount:
                    amount = fixed_amount
                else:  # fee_fixing
                    amount = prop.rateable_value * prop.rate_impost
                
                records.append({
                    'type': 'Property',
                    'id': prop.id,
                    'account_no': prop.account_no,
                    'name': prop.owner_name,
                    'electoral_area': prop.electoral_area,
                    'town': prop.town,
                    'amount': amount,
                    'has_invoice': existing_invoice is not None
                })
                
                property_count += 1
                total_amount += amount
        
        # Get businesses
        if bill_type in ['all', 'business']:
            query = BusinessOccupant.query
            
            # Apply filters
            if electoral_area != 'all':
                query = query.filter_by(electoral_area=electoral_area)
            if town != 'all':
                query = query.filter_by(town=town)
            
            businesses = query.all()
            
            for business in businesses:
                # Check if invoice already exists
                existing_invoice = BOPInvoice.query.filter_by(
                    business_id=business.id,
                    year=year
                ).first()
                
                # Skip if normal run and invoice exists
                if run_type == 'normal' and existing_invoice:
                    continue
                
                # Calculate amount
                if amount_type == 'fixed_amount' and fixed_amount:
                    amount = fixed_amount
                    product_name = 'Fixed Rate'
                else:  # fee_fixing
                    # Find matching product
                    def normalize_category(cat_value):
                        if not cat_value or cat_value in ['', 'N/A', '-', 'NONE']:
                            return None
                        return str(cat_value).strip()
                    
                    cat1 = normalize_category(business.category1)
                    cat2 = normalize_category(business.category2)
                    cat3 = normalize_category(business.category3)
                    cat4 = normalize_category(business.category4)
                    cat5 = normalize_category(business.category5)
                    cat6 = normalize_category(business.category6)
                    
                    # Find product
                    query_prod = Product.query
                    
                    for i, cat_val in enumerate([cat1, cat2, cat3, cat4, cat5, cat6], 1):
                        col = getattr(Product, f'category{i}')
                        if cat_val is None:
                            query_prod = query_prod.filter(col.is_(None))
                        else:
                            query_prod = query_prod.filter(col == cat_val)
                    
                    product = query_prod.first()
                    
                    if product:
                        amount = product.amount
                        product_name = '-'.join([str(p) if p else 'N/A' for p in [cat1, cat2, cat3, cat4, cat5, cat6]])
                    else:
                        # Skip if no product found
                        continue
                
                records.append({
                    'type': 'Business',
                    'id': business.id,
                    'account_no': business.account_no,
                    'name': business.business_name,
                    'electoral_area': business.electoral_area,
                    'town': business.town,
                    'amount': amount,
                    'has_invoice': existing_invoice is not None
                })
                
                business_count += 1
                total_amount += amount
        
        return jsonify({
            'success': True,
            'preview': {
                'total_records': len(records),
                'property_count': property_count,
                'business_count': business_count,
                'total_amount': total_amount,
                'records': records[:100]  # Limit to first 100 for display
            }
        })
        
    except Exception as e:
        app.logger.error(f'Error in batch preview: {str(e)}', exc_info=True)
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/api/batch-invoice/generate', methods=['POST'])
@login_required
def batch_invoice_generate():
    """Generate invoices in batch"""
    try:
        data = request.get_json()
        
        year = int(data.get('year'))
        bill_type = data.get('billType')
        run_type = data.get('runType')
        amount_type = data.get('amountType')
        fixed_amount = float(data.get('fixedAmount', 0)) if data.get('fixedAmount') else None
        electoral_area = data.get('electoralArea')
        town = data.get('town')
        
        created_count = 0
        skipped_count = 0
        failed_count = 0
        errors = []
        
        # Today's date for invoices
        today = datetime.now().date()
        due_date = today + timedelta(days=30)
        
        # Generate property invoices
        if bill_type in ['all', 'property']:
            query = Property.query
            
            if electoral_area != 'all':
                query = query.filter_by(electoral_area=electoral_area)
            if town != 'all':
                query = query.filter_by(town=town)
            
            properties = query.all()
            
            for prop in properties:
                try:
                    # Check existing
                    existing = PropertyInvoice.query.filter_by(
                        property_id=prop.id,
                        year=year
                    ).first()
                    
                    if run_type == 'normal' and existing:
                        skipped_count += 1
                        continue
                    
                    # Calculate amount
                    if amount_type == 'fixed_amount' and fixed_amount:
                        base_amount = fixed_amount
                        rate_impost = 0.0
                    else:
                        base_amount = prop.rateable_value * prop.rate_impost
                        rate_impost = prop.rate_impost
                    
                    if existing and run_type == 'force':
                        # Update existing
                        existing.amount = base_amount
                        existing.total_amount = base_amount
                        existing.rateable_value = prop.rateable_value
                        existing.rate_impost = rate_impost
                        existing.invoice_date = today
                        existing.due_date = due_date
                        created_count += 1
                    else:
                        # Create new
                        invoice = PropertyInvoice(
                            invoice_no=generate_property_invoice_no(prop.id, year),
                            property_id=prop.id,
                            year=year,
                            rateable_value=prop.rateable_value,
                            rate_impost=rate_impost,
                            amount=base_amount,
                            total_amount=base_amount,
                            invoice_date=today,
                            due_date=due_date,
                            status='Unpaid',
                            description='Batch generated invoice'
                        )
                        db.session.add(invoice)
                        created_count += 1
                    
                except Exception as e:
                    failed_count += 1
                    errors.append(f'Property {prop.account_no}: {str(e)}')
        
        # Generate business invoices
        if bill_type in ['all', 'business']:
            query = BusinessOccupant.query
            
            if electoral_area != 'all':
                query = query.filter_by(electoral_area=electoral_area)
            if town != 'all':
                query = query.filter_by(town=town)
            
            businesses = query.all()
            
            for business in businesses:
                try:
                    # Check existing
                    existing = BOPInvoice.query.filter_by(
                        business_id=business.id,
                        year=year
                    ).first()
                    
                    if run_type == 'normal' and existing:
                        skipped_count += 1
                        continue
                    
                    # Calculate amount
                    if amount_type == 'fixed_amount' and fixed_amount:
                        amount = fixed_amount
                        product_name = 'Fixed Rate'
                    else:
                        # Find product
                        def normalize_category(cat_value):
                            if not cat_value or cat_value in ['', 'N/A', '-', 'NONE']:
                                return None
                            return str(cat_value).strip()
                        
                        cat1 = normalize_category(business.category1)
                        cat2 = normalize_category(business.category2)
                        cat3 = normalize_category(business.category3)
                        cat4 = normalize_category(business.category4)
                        cat5 = normalize_category(business.category5)
                        cat6 = normalize_category(business.category6)
                        
                        query_prod = Product.query
                        for i, cat_val in enumerate([cat1, cat2, cat3, cat4, cat5, cat6], 1):
                            col = getattr(Product, f'category{i}')
                            if cat_val is None:
                                query_prod = query_prod.filter(col.is_(None))
                            else:
                                query_prod = query_prod.filter(col == cat_val)
                        
                        product = query_prod.first()
                        
                        if not product:
                            skipped_count += 1
                            continue
                        
                        amount = product.amount
                        product_name = '-'.join([str(p) if p else 'N/A' for p in [cat1, cat2, cat3, cat4, cat5, cat6]])
                    
                    if existing and run_type == 'force':
                        # Update existing
                        existing.amount = amount
                        existing.total_amount = amount
                        existing.product_name = product_name
                        existing.invoice_date = today
                        existing.due_date = due_date
                        created_count += 1
                    else:
                        # Create new
                        invoice = BOPInvoice(
                            invoice_no=generate_business_invoice_no(business.business_id, year),
                            business_id=business.id,
                            product_name=product_name,
                            amount=amount,
                            total_amount=amount,
                            year=year,
                            invoice_date=today,
                            due_date=due_date,
                            status='Unpaid',
                            description='Batch generated invoice'
                        )
                        db.session.add(invoice)
                        created_count += 1
                    
                except Exception as e:
                    failed_count += 1
                    errors.append(f'Business {business.account_no}: {str(e)}')
        
        # Commit all changes
        db.session.commit()
        
        # Log action
        log_action('Batch invoice generation', 
                  details=f'Year: {year}, Type: {bill_type}, Created: {created_count}, Skipped: {skipped_count}, Failed: {failed_count}')
        
        return jsonify({
            'success': True,
            'result': {
                'created': created_count,
                'skipped': skipped_count,
                'failed': failed_count,
                'errors': errors[:20]  # First 20 errors
            }
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error in batch generation: {str(e)}', exc_info=True)
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# ==================== Password Management Routes ====================
# Add these routes to your app.py file

from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime, timedelta
import re

# Add this near your other imports at the top of app.py
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Password validation function
def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password meets requirements"

# 1. Change Password Route (for logged-in users)
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allow logged-in users to change their password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Verify current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('admin/change_password.html')
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('admin/change_password.html')
        
        # Validate password strength
        is_valid, message = validate_password_strength(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template('admin/change_password.html')
        
        # Check if new password is same as current
        if current_user.check_password(new_password):
            flash('New password must be different from current password', 'error')
            return render_template('admin/change_password.html')
        
        # Update password
        current_user.set_password(new_password)
        current_user.is_temp_password = False
        db.session.commit()
        
        log_action('Password changed', 'User', current_user.id)
        flash('Password changed successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('admin/change_password.html')

# 2. Change Temporary Password Route (for first-time login)
@app.route('/change-temp-password', methods=['GET', 'POST'])
@login_required
def change_temp_password():
    """Force users with temporary passwords to change them"""
    if not current_user.is_temp_password:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        temp_password = request.form.get('temp_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Verify temporary password
        if not current_user.check_password(temp_password):
            flash('Temporary password is incorrect', 'error')
            return render_template('admin/temp_password.html')
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('admin/temp_password.html')
        
        # Validate password strength
        is_valid, message = validate_password_strength(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template('admin/temp_password.html')
        
        # Check if new password is same as temporary
        if current_user.check_password(new_password):
            flash('New password must be different from temporary password', 'error')
            return render_template('admin/temp_password.html')
        
        # Update password and remove temp flag
        current_user.set_password(new_password)
        current_user.is_temp_password = False
        db.session.commit()
        
        log_action('Temporary password changed', 'User', current_user.id)
        flash('Password changed successfully! You can now use the system.', 'success')
        return redirect(url_for('index'))
    
    return render_template('admin/temp_password.html')

# 3. Forgot Password Route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Send password reset link to user's email/phone"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email_or_phone = request.form.get('email_or_phone', '').strip()
        
        # Find user by email or phone
        user = User.query.filter(
            db.or_(
                User.email == email_or_phone,
                User.phone_number == email_or_phone
            )
        ).first()
        
        if user:
            # Generate reset token
            token = serializer.dumps(user.email, salt='password-reset-salt')
            
            # Create reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # Log the action
            log_action('Password reset requested', 'User', user.id, f'Email/Phone: {email_or_phone}')
            
            # TODO: Send email/SMS with reset link
            # For now, we'll just flash the link (in production, send via email/SMS)
            app.logger.info(f'Password reset link for {user.username}: {reset_link}')
            
            flash(f'Password reset instructions have been sent to your registered contact. '
                  f'Reset link (for testing): {reset_link}', 'success')
        else:
            # Don't reveal if user exists or not (security best practice)
            flash('If that email or phone number is registered, you will receive reset instructions.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('admin/forgot_password.html')

# 4. Reset Password Route (with token)
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password using token from email/SMS"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    try:
        # Verify token (expires after 1 hour)
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Invalid reset link', 'error')
            return redirect(url_for('forgot_password'))
        
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Check if passwords match
            if new_password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('admin/reset_password.html', token=token, token_valid=True)
            
            # Validate password strength
            is_valid, message = validate_password_strength(new_password)
            if not is_valid:
                flash(message, 'error')
                return render_template('admin/reset_password.html', token=token, token_valid=True)
            
            # Update password
            user.set_password(new_password)
            user.is_temp_password = False
            db.session.commit()
            
            log_action('Password reset completed', 'User', user.id)
            flash('Password reset successfully! You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
        
        return render_template('admin/reset_password.html', token=token, token_valid=True)
        
    except SignatureExpired:
        flash('Password reset link has expired. Please request a new one.', 'error')
        return render_template('admin/reset_password.html', token=token, token_valid=False)
    except BadSignature:
        flash('Invalid password reset link', 'error')
        return render_template('admin/reset_password.html', token=token, token_valid=False)

# 5. Edit User Route (Admin only)
@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    """Edit user details - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        role = request.form.get('role')
        reset_password = request.form.get('reset_password') == 'true'
        
        # Check if username is taken by another user
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != user.id:
            flash('Username already exists', 'error')
            return render_template('admin/edit_user.html', user=user)
        
        # Check if email is taken by another user
        existing_email = User.query.filter_by(email=email).first()
        if existing_email and existing_email.id != user.id:
            flash('Email already registered', 'error')
            return render_template('admin/edit_user.html', user=user)
        
        # Update user details
        user.username = username
        user.email = email
        user.phone_number = phone_number
        user.role = role
        
        # Force password reset if requested
        if reset_password:
            user.is_temp_password = True
        
        db.session.commit()
        
        log_action('User updated', 'User', user.id, 
                  f'Username: {username}, Role: {role}, Force reset: {reset_password}')
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/edit_user.html', user=user)

# 6. Confirm Delete User Route (Admin only)
@app.route('/admin/user/<int:user_id>/confirm-delete')
@login_required
def confirm_delete_user(user_id):
    """Show confirmation page before deleting user - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/confirm_delete_user.html', user=user)

# Optional: Add this route to view/manage password reset tokens (Admin only)

@app.route('/admin/reset-tokens')
@login_required
def view_reset_tokens():
    """View all password reset tokens - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    page = request.args.get('page', 1, type=int)
    
    # Get all tokens, newest first
    pagination = PasswordResetToken.query.order_by(
        PasswordResetToken.created_at.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    
    return render_template('admin/reset_tokens.html', pagination=pagination)

@app.route('/admin/reset-token/<int:token_id>/revoke', methods=['POST'])
@login_required
def revoke_reset_token(token_id):
    """Revoke/invalidate a password reset token - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    token = PasswordResetToken.query.get_or_404(token_id)
    
    if not token.used:
        token.used = True
        token.used_at = datetime.utcnow()
        db.session.commit()
        
        log_action('Password reset token revoked', 'PasswordResetToken', token_id)
        flash('Token revoked successfully', 'success')
    else:
        flash('Token already used or revoked', 'info')
    
    return redirect(url_for('view_reset_tokens'))

@app.route('/admin/reset-tokens/cleanup', methods=['POST'])
@login_required
def cleanup_expired_tokens():
    """Delete expired and used tokens - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Delete tokens that are expired or used and older than 30 days
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        deleted = PasswordResetToken.query.filter(
            db.or_(
                PasswordResetToken.expires_at < datetime.utcnow(),
                db.and_(
                    PasswordResetToken.used == True,
                    PasswordResetToken.created_at < cutoff_date
                )
            )
        ).delete()
        
        db.session.commit()
        
        log_action('Password reset tokens cleaned up', details=f'{deleted} tokens deleted')
        flash(f'Successfully cleaned up {deleted} expired/old tokens', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error cleaning up tokens: {str(e)}')
        flash('Error cleaning up tokens', 'error')
    
    return redirect(url_for('view_reset_tokens'))

# ==================== Adjustment Routes ====================

@app.route('/invoice/property/<int:invoice_id>/adjustment/create', methods=['GET', 'POST'])
@login_required
def create_property_adjustment(invoice_id):
    """Create adjustment for property invoice"""
    invoice = PropertyInvoice.query.get_or_404(invoice_id)
    
    if request.method == 'POST':
        try:
            adjustment_type = request.form.get('adjustment_type')
            adjustment_amount = float(request.form.get('adjustment_amount', 0))
            reason = request.form.get('reason')
            description = request.form.get('description')
            
            # Validate inputs
            if not adjustment_type or not reason or not description:
                flash('Please fill in all required fields', 'error')
                return redirect(url_for('create_property_adjustment', invoice_id=invoice_id))
            
            if adjustment_amount == 0:
                flash('Adjustment amount cannot be zero', 'error')
                return redirect(url_for('create_property_adjustment', invoice_id=invoice_id))
            
            # Get current invoice total
            current_amount = invoice.total_amount or invoice.amount
            
            # Calculate new amount based on adjustment type
            if adjustment_type == 'Credit':
                # Credit reduces the amount (negative adjustment)
                adjustment_amount = -abs(adjustment_amount)
            elif adjustment_type == 'Penalty':
                # Penalty increases the amount (positive adjustment)
                adjustment_amount = abs(adjustment_amount)
            elif adjustment_type == 'Waiver':
                # Waiver reduces the amount (negative adjustment)
                adjustment_amount = -abs(adjustment_amount)
            # For 'Amount Adjustment', use the sign as entered
            
            new_amount = current_amount + adjustment_amount
            
            # Prevent negative amounts
            if new_amount < 0:
                flash('Adjustment would result in negative invoice amount', 'error')
                return redirect(url_for('create_property_adjustment', invoice_id=invoice_id))
            
            # Check if adjustment requires approval (>10% change or >GHS 1000)
            percentage_change = abs((adjustment_amount / current_amount) * 100)
            requires_approval = (percentage_change > 10) or (abs(adjustment_amount) > 1000)
            
            # Handle file upload
            supporting_doc = None
            if 'supporting_document' in request.files:
                file = request.files['supporting_document']
                if file and file.filename:
                    is_valid, message = validate_file_upload(file, allowed_extensions={'pdf', 'jpg', 'jpeg', 'png'})
                    if is_valid:
                        filename = secure_filename(file.filename)
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = f"adjustment_{invoice_id}_{timestamp}_{filename}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        supporting_doc = filename
            
            # Create adjustment record
            adjustment = InvoiceAdjustment(
                property_invoice_id=invoice.id,
                invoice_type='Property',
                invoice_no=invoice.invoice_no,
                adjustment_type=adjustment_type,
                original_amount=current_amount,
                adjustment_amount=adjustment_amount,
                new_amount=new_amount,
                reason=reason,
                description=description,
                supporting_document=supporting_doc,
                requires_approval=requires_approval,
                status='Pending' if requires_approval else 'Approved',
                created_by=current_user.id,
                approved_by=current_user.id if not requires_approval else None,
                approved_at=datetime.utcnow() if not requires_approval else None
            )
            
            db.session.add(adjustment)
            
            # Apply adjustment immediately if no approval required
            if not requires_approval:
                invoice.total_amount = new_amount
                if invoice.amount == current_amount:
                    invoice.amount = new_amount
            
            db.session.commit()
            
            log_action('Adjustment created', 'InvoiceAdjustment', adjustment.id, 
                      f'Invoice: {invoice.invoice_no}, Type: {adjustment_type}, Amount: {adjustment_amount}')
            
            if requires_approval:
                flash(f'Adjustment created successfully and sent for approval! (±{percentage_change:.1f}% change)', 'success')
            else:
                flash('Adjustment applied successfully!', 'success')
            
            return redirect(url_for('view_property_invoice', invoice_id=invoice.id))
            
        except ValueError as e:
            db.session.rollback()
            flash(f'Invalid adjustment amount: {str(e)}', 'error')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating adjustment: {str(e)}')
            flash(f'Error creating adjustment: {str(e)}', 'error')
    
    # GET request - show form with adjustment history
    adjustments = InvoiceAdjustment.query.filter_by(
        property_invoice_id=invoice_id,
        invoice_type='Property'
    ).order_by(InvoiceAdjustment.created_at.desc()).all()
    
    return render_template('property_adjustment_form.html', 
                         invoice=invoice,
                         property=invoice.property,
                         adjustments=adjustments)


@app.route('/invoice/business/<int:invoice_id>/adjustment/create', methods=['GET', 'POST'])
@login_required
def create_business_adjustment(invoice_id):
    """Create adjustment for business invoice"""
    invoice = BOPInvoice.query.get_or_404(invoice_id)
    
    if request.method == 'POST':
        try:
            adjustment_type = request.form.get('adjustment_type')
            adjustment_amount = float(request.form.get('adjustment_amount', 0))
            reason = request.form.get('reason')
            description = request.form.get('description')
            
            if not adjustment_type or not reason or not description:
                flash('Please fill in all required fields', 'error')
                return redirect(url_for('create_business_adjustment', invoice_id=invoice_id))
            
            if adjustment_amount == 0:
                flash('Adjustment amount cannot be zero', 'error')
                return redirect(url_for('create_business_adjustment', invoice_id=invoice_id))
            
            current_amount = invoice.total_amount or invoice.amount
            
            # Calculate adjustment based on type
            if adjustment_type == 'Credit':
                adjustment_amount = -abs(adjustment_amount)
            elif adjustment_type == 'Penalty':
                adjustment_amount = abs(adjustment_amount)
            elif adjustment_type == 'Waiver':
                adjustment_amount = -abs(adjustment_amount)
            
            new_amount = current_amount + adjustment_amount
            
            if new_amount < 0:
                flash('Adjustment would result in negative invoice amount', 'error')
                return redirect(url_for('create_business_adjustment', invoice_id=invoice_id))
            
            percentage_change = abs((adjustment_amount / current_amount) * 100)
            requires_approval = (percentage_change > 10) or (abs(adjustment_amount) > 1000)
            
            # Handle file upload
            supporting_doc = None
            if 'supporting_document' in request.files:
                file = request.files['supporting_document']
                if file and file.filename:
                    is_valid, message = validate_file_upload(file, allowed_extensions={'pdf', 'jpg', 'jpeg', 'png'})
                    if is_valid:
                        filename = secure_filename(file.filename)
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = f"adjustment_{invoice_id}_{timestamp}_{filename}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        supporting_doc = filename
            
            adjustment = InvoiceAdjustment(
                business_invoice_id=invoice.id,
                invoice_type='Business',
                invoice_no=invoice.invoice_no,
                adjustment_type=adjustment_type,
                original_amount=current_amount,
                adjustment_amount=adjustment_amount,
                new_amount=new_amount,
                reason=reason,
                description=description,
                supporting_document=supporting_doc,
                requires_approval=requires_approval,
                status='Pending' if requires_approval else 'Approved',
                created_by=current_user.id,
                approved_by=current_user.id if not requires_approval else None,
                approved_at=datetime.utcnow() if not requires_approval else None
            )
            
            db.session.add(adjustment)
            
            if not requires_approval:
                invoice.total_amount = new_amount
                if invoice.amount == current_amount:
                    invoice.amount = new_amount
            
            db.session.commit()
            
            log_action('Adjustment created', 'InvoiceAdjustment', adjustment.id, 
                      f'Invoice: {invoice.invoice_no}, Type: {adjustment_type}, Amount: {adjustment_amount}')
            
            if requires_approval:
                flash(f'Adjustment created successfully and sent for approval! (±{percentage_change:.1f}% change)', 'success')
            else:
                flash('Adjustment applied successfully!', 'success')
            
            return redirect(url_for('view_business_invoice', invoice_id=invoice.id))
            
        except ValueError as e:
            db.session.rollback()
            flash(f'Invalid adjustment amount: {str(e)}', 'error')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating adjustment: {str(e)}')
            flash(f'Error creating adjustment: {str(e)}', 'error')
    
    adjustments = InvoiceAdjustment.query.filter_by(
        business_invoice_id=invoice_id,
        invoice_type='Business'
    ).order_by(InvoiceAdjustment.created_at.desc()).all()
    
    return render_template('business_adjustment_form.html', 
                         invoice=invoice,
                         business=invoice.business,
                         adjustments=adjustments)


@app.route('/admin/adjustments/pending')
@login_required
def pending_adjustments():
    """View all pending adjustments requiring approval (admin only)"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    pending = InvoiceAdjustment.query.filter_by(
        status='Pending',
        requires_approval=True
    ).order_by(InvoiceAdjustment.created_at.desc()).all()
    
    return render_template('admin/pending_adjustments.html', adjustments=pending)


@app.route('/admin/adjustment/<int:adjustment_id>/approve', methods=['POST'])
@login_required
def approve_adjustment(adjustment_id):
    """Approve a pending adjustment (admin only)"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    adjustment = InvoiceAdjustment.query.get_or_404(adjustment_id)
    
    if adjustment.status != 'Pending':
        flash('This adjustment has already been processed', 'warning')
        return redirect(url_for('pending_adjustments'))
    
    try:
        approval_notes = request.form.get('approval_notes', '')
        
        # Update adjustment status
        adjustment.status = 'Approved'
        adjustment.approved_by = current_user.id
        adjustment.approved_at = datetime.utcnow()
        adjustment.approval_notes = approval_notes
        
        # Apply the adjustment to the invoice
        if adjustment.invoice_type == 'Property':
            invoice = adjustment.property_invoice
            invoice.total_amount = adjustment.new_amount
            if invoice.amount == adjustment.original_amount:
                invoice.amount = adjustment.new_amount
        else:
            invoice = adjustment.business_invoice
            invoice.total_amount = adjustment.new_amount
            if invoice.amount == adjustment.original_amount:
                invoice.amount = adjustment.new_amount
        
        db.session.commit()
        
        log_action('Adjustment approved', 'InvoiceAdjustment', adjustment_id, 
                  f'Invoice: {adjustment.invoice_no}')
        flash('Adjustment approved and applied successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error approving adjustment: {str(e)}')
        flash(f'Error approving adjustment: {str(e)}', 'error')
    
    return redirect(url_for('pending_adjustments'))


@app.route('/admin/adjustment/<int:adjustment_id>/reject', methods=['POST'])
@login_required
def reject_adjustment(adjustment_id):
    """Reject a pending adjustment (admin only)"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    adjustment = InvoiceAdjustment.query.get_or_404(adjustment_id)
    
    if adjustment.status != 'Pending':
        flash('This adjustment has already been processed', 'warning')
        return redirect(url_for('pending_adjustments'))
    
    try:
        rejection_notes = request.form.get('rejection_notes', '')
        
        adjustment.status = 'Rejected'
        adjustment.approved_by = current_user.id
        adjustment.approved_at = datetime.utcnow()
        adjustment.approval_notes = rejection_notes
        
        db.session.commit()
        
        log_action('Adjustment rejected', 'InvoiceAdjustment', adjustment_id, 
                  f'Invoice: {adjustment.invoice_no}')
        flash('Adjustment rejected', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error rejecting adjustment: {str(e)}')
        flash(f'Error rejecting adjustment: {str(e)}', 'error')
    
    return redirect(url_for('pending_adjustments'))

# ==================== OTP API Routes ====================

@app.route('/api/send-otp', methods=['POST'])
@login_required
def send_otp():
    """Send OTP to payer's phone number"""
    try:
        data = request.get_json()
        
        # Validate required fields
        phone_number = data.get('phone_number')
        invoice_id = data.get('invoice_id')
        invoice_type = data.get('invoice_type')
        payment_amount = data.get('payment_amount')
        
        if not all([phone_number, invoice_id, invoice_type, payment_amount]):
            log_action('OTP send failed - Missing fields', 
                      invoice_type, 
                      invoice_id,
                      f'Phone: {phone_number}, Amount: {payment_amount}')
            return jsonify({
                'success': False,
                'message': 'Missing required fields'
            }), 400
        
        # Format phone number
        success, formatted_phone, error = format_phone_number(phone_number)
        if not success:
            log_action('OTP send failed - Invalid phone', 
                      invoice_type, 
                      invoice_id,
                      f'Phone: {phone_number}, Error: {error}')
            return jsonify({
                'success': False,
                'message': error
            }), 400
        
        # Validate invoice exists
        if invoice_type == 'Property':
            invoice = PropertyInvoice.query.get(invoice_id)
        else:
            invoice = BOPInvoice.query.get(invoice_id)
        
        if not invoice:
            log_action('OTP send failed - Invoice not found', 
                      invoice_type, 
                      invoice_id,
                      f'Phone: {formatted_phone}')
            return jsonify({
                'success': False,
                'message': 'Invoice not found'
            }), 404
        
        # Check for existing valid OTP
        existing_otp = OTPVerification.query.filter_by(
            phone_number=formatted_phone,
            invoice_id=invoice_id,
            invoice_type=invoice_type,
            verified=False
        ).filter(
            OTPVerification.expires_at > datetime.utcnow()
        ).first()
        
        if existing_otp:
            # Delete old OTP to generate new one
            db.session.delete(existing_otp)
            db.session.commit()
            log_action('OTP regenerated - Old OTP deleted', 
                      invoice_type, 
                      invoice_id,
                      f'Phone: {formatted_phone}')
        
        # Generate new OTP
        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
        
        # Send OTP via SMS
        success, message = send_otp_sms(formatted_phone, otp_code, float(payment_amount))
        
        if not success:
            log_action('OTP send failed - SMS error', 
                      invoice_type, 
                      invoice_id,
                      f'Phone: {formatted_phone}, Provider: {SMS_PROVIDER}, Error: {message}')
            return jsonify({
                'success': False,
                'message': message,
                'provider': SMS_PROVIDER
            }), 500
        
        # Store OTP in database
        otp_record = OTPVerification(
            phone_number=formatted_phone,
            otp_code=otp_code,
            invoice_id=invoice_id,
            invoice_type=invoice_type,
            payment_amount=float(payment_amount),
            expires_at=expires_at
        )
        db.session.add(otp_record)
        db.session.commit()
        
        # ✅ LOG SUCCESS
        log_action(
            'OTP sent successfully',
            invoice_type,
            invoice_id,
            f'Phone: {formatted_phone}, Amount: GHS {payment_amount:,.2f}, Provider: {SMS_PROVIDER}, OTP ID: {otp_record.id}'
        )
        
        return jsonify({
            'success': True,
            'message': message,
            'otp_id': otp_record.id,
            'expires_in_minutes': OTP_EXPIRY_MINUTES,
            'provider': SMS_PROVIDER
        }), 200
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error sending OTP: {str(e)}', exc_info=True)
        
        # Log the error
        log_action(
            'OTP send error',
            data.get('invoice_type') if data else None,
            data.get('invoice_id') if data else None,
            f'Error: {str(e)}'
        )
        
        return jsonify({
            'success': False,
            'message': 'An error occurred while sending OTP',
            'error': str(e)
        }), 500

@app.route('/api/resend-otp', methods=['POST'])
@login_required
def resend_otp():
    """Resend OTP to the same phone number"""
    try:
        data = request.get_json()
        otp_id = data.get('otp_id')
        
        if not otp_id:
            log_action('OTP resend failed - Missing OTP ID')
            return jsonify({
                'success': False,
                'message': 'OTP ID is required'
            }), 400
        
        # Get existing OTP record
        old_otp = OTPVerification.query.get(otp_id)
        
        if not old_otp:
            log_action('OTP resend failed - Invalid ID',
                      details=f'OTP ID: {otp_id}')
            return jsonify({
                'success': False,
                'message': 'Invalid OTP ID'
            }), 404
        
        # Generate new OTP
        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
        
        # Send OTP
        success, message = send_otp_sms(old_otp.phone_number, otp_code, old_otp.payment_amount)
        
        if not success:
            log_action('OTP resend failed - SMS error',
                      old_otp.invoice_type,
                      old_otp.invoice_id,
                      f'Phone: {old_otp.phone_number}, Provider: {SMS_PROVIDER}, Error: {message}')
            return jsonify({
                'success': False,
                'message': message,
                'provider': SMS_PROVIDER
            }), 500
        
        # Create new OTP record
        new_otp = OTPVerification(
            phone_number=old_otp.phone_number,
            otp_code=otp_code,
            invoice_id=old_otp.invoice_id,
            invoice_type=old_otp.invoice_type,
            payment_amount=old_otp.payment_amount,
            expires_at=expires_at
        )
        db.session.add(new_otp)
        
        # Mark old OTP as used
        old_otp.verified = True
        
        db.session.commit()
        
        # ✅ LOG SUCCESS
        log_action(
            'OTP resent successfully',
            old_otp.invoice_type,
            old_otp.invoice_id,
            f'Phone: {old_otp.phone_number}, Provider: {SMS_PROVIDER}, New OTP ID: {new_otp.id}'
        )
        
        return jsonify({
            'success': True,
            'message': message,
            'otp_id': new_otp.id,
            'expires_in_minutes': OTP_EXPIRY_MINUTES,
            'provider': SMS_PROVIDER
        }), 200
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error resending OTP: {str(e)}', exc_info=True)
        
        log_action('OTP resend error',
                  details=f'Error: {str(e)}')
        
        return jsonify({
            'success': False,
            'message': 'An error occurred while resending OTP'
        }), 500
        
@app.route('/api/verify-otp', methods=['POST'])
@login_required
def verify_otp():
    """Verify OTP code"""
    try:
        data = request.get_json()
        
        otp_id = data.get('otp_id')
        otp_code = data.get('otp_code')
        
        if not otp_id or not otp_code:
            log_action('OTP verification failed - Missing data',
                      details=f'OTP ID: {otp_id}')
            return jsonify({
                'success': False,
                'message': 'OTP ID and code are required'
            }), 400
        
        # Get OTP record
        otp_record = OTPVerification.query.get(otp_id)
        
        if not otp_record:
            log_action('OTP verification failed - Invalid ID',
                      details=f'OTP ID: {otp_id}')
            return jsonify({
                'success': False,
                'message': 'Invalid OTP'
            }), 404
        
        # Check if already verified
        if otp_record.verified:
            log_action('OTP verification failed - Already used',
                      otp_record.invoice_type,
                      otp_record.invoice_id,
                      f'Phone: {otp_record.phone_number}, OTP ID: {otp_id}')
            return jsonify({
                'success': False,
                'message': 'OTP already used'
            }), 400
        
        # Check if expired
        if otp_record.is_expired():
            log_action('OTP verification failed - Expired',
                      otp_record.invoice_type,
                      otp_record.invoice_id,
                      f'Phone: {otp_record.phone_number}, OTP ID: {otp_id}')
            return jsonify({
                'success': False,
                'message': 'OTP has expired. Please request a new one.'
            }), 400
        
        # Check attempts limit
        if otp_record.attempts >= 3:
            log_action('OTP verification failed - Too many attempts',
                      otp_record.invoice_type,
                      otp_record.invoice_id,
                      f'Phone: {otp_record.phone_number}, Attempts: {otp_record.attempts}')
            return jsonify({
                'success': False,
                'message': 'Too many failed attempts. Please request a new OTP.'
            }), 400
        
        # Increment attempts
        otp_record.attempts += 1
        db.session.commit()
        
        # Verify OTP code
        if otp_record.otp_code != otp_code:
            log_action('OTP verification failed - Wrong code',
                      otp_record.invoice_type,
                      otp_record.invoice_id,
                      f'Phone: {otp_record.phone_number}, Attempts: {otp_record.attempts}/3')
            return jsonify({
                'success': False,
                'message': f'Invalid OTP code. {3 - otp_record.attempts} attempts remaining.',
                'attempts_remaining': 3 - otp_record.attempts
            }), 400
        
        # Mark as verified
        otp_record.verified = True
        db.session.commit()
        
        # ✅ LOG SUCCESS
        log_action(
            'OTP verified successfully',
            otp_record.invoice_type,
            otp_record.invoice_id,
            f'Phone: {otp_record.phone_number}, Amount: GHS {otp_record.payment_amount:,.2f}'
        )
        
        return jsonify({
            'success': True,
            'message': 'OTP verified successfully',
            'otp_id': otp_record.id
        }), 200
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error verifying OTP: {str(e)}', exc_info=True)
        
        log_action('OTP verification error',
                  details=f'Error: {str(e)}')
        
        return jsonify({
            'success': False,
            'message': 'An error occurred while verifying OTP'
        }), 500
        
@app.route('/admin/sms-status')
@login_required
def sms_status():
    """View SMS provider configuration status - Admin only"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    status_data = {
        'provider': SMS_PROVIDER,
        'expiry_minutes': OTP_EXPIRY_MINUTES,
        'twilio_sid': TWILIO_ACCOUNT_SID is not None,
        'twilio_token': TWILIO_AUTH_TOKEN is not None,
        'twilio_phone': TWILIO_PHONE_NUMBER,
        'at_username': AFRICASTALKING_USERNAME,
        'at_key': AFRICASTALKING_API_KEY is not None,  # ✅ FIXED THIS LINE
        'vonage_key': VONAGE_API_KEY is not None,
        'vonage_secret': VONAGE_API_SECRET is not None,
        'vonage_sender': VONAGE_SENDER_ID,
        'smtp_configured': SMTP_USERNAME is not None and SMTP_PASSWORD is not None
    }
    
    return render_template('admin/sms_status.html', status=status_data)
# ==================== Batch Printing Routes ====================

@app.route('/batch-print', methods=['GET', 'POST'])
@login_required
def batch_print():
    """Batch print invoices by account numbers"""
    if request.method == 'POST':
        try:
            invoice_type = request.form.get('invoice_type')
            account_numbers = request.form.get('account_numbers', '').strip()
            year_filter = request.form.get('year_filter')
            
            if not invoice_type or not account_numbers:
                flash('Please select invoice type and enter account numbers', 'error')
                return redirect(url_for('batch_print'))
            
            # Parse account numbers (comma or newline separated)
            account_list = [acc.strip().upper() for acc in account_numbers.replace('\n', ',').split(',') if acc.strip()]
            
            if not account_list:
                flash('No valid account numbers provided', 'error')
                return redirect(url_for('batch_print'))
            
            # Store in session for the print preview page
            session['batch_print_data'] = {
                'invoice_type': invoice_type,
                'account_numbers': account_list,
                'year_filter': year_filter
            }
            
            log_action('Batch print initiated', 
                      details=f'Type: {invoice_type}, Accounts: {len(account_list)}')
            
            return redirect(url_for('batch_print_preview'))
            
        except Exception as e:
            app.logger.error(f'Error in batch print: {str(e)}')
            flash(f'Error processing batch print: {str(e)}', 'error')
    
    # GET request - show form
    return render_template('batch_print.html')


@app.route('/batch-print/preview')
@login_required
def batch_print_preview():
    """Preview invoices before batch printing"""
    batch_data = session.get('batch_print_data')
    
    if not batch_data:
        flash('No batch print data found. Please start a new batch print.', 'error')
        return redirect(url_for('batch_print'))
    
    invoice_type = batch_data['invoice_type']
    account_numbers = batch_data['account_numbers']
    year_filter = batch_data.get('year_filter')
    
    results = {
        'found': [],
        'not_found': [],
        'invoice_type': invoice_type
    }
    
    try:
        if invoice_type in ['Property', 'ALL']:
            # Search property invoices
            properties = Property.query.filter(
                Property.account_no.in_(account_numbers)
            ).all()
            
            for prop in properties:
                # Get invoices for this property
                query = PropertyInvoice.query.filter_by(property_id=prop.id)
                
                if year_filter:
                    query = query.filter_by(year=int(year_filter))
                
                invoices = query.order_by(PropertyInvoice.year.desc()).all()
                
                for invoice in invoices:
                    # Calculate payment info
                    payments = Payment.query.filter_by(
                        property_invoice_id=invoice.id
                    ).all()
                    total_paid = sum(p.payment_amount for p in payments)
                    
                    results['found'].append({
                        'type': 'Property',
                        'account_no': prop.account_no,
                        'owner_name': prop.owner_name,
                        'invoice_no': invoice.invoice_no,
                        'invoice_id': invoice.id,
                        'year': invoice.year,
                        'amount': invoice.total_amount or invoice.amount,
                        'paid': total_paid,
                        'status': invoice.status
                    })
        
        if invoice_type in ['BOP', 'ALL']:
            # Search business invoices
            businesses = BusinessOccupant.query.filter(
                BusinessOccupant.account_no.in_(account_numbers)
            ).all()
            
            for business in businesses:
                # Get invoices for this business
                query = BOPInvoice.query.filter_by(business_id=business.id)
                
                if year_filter:
                    query = query.filter_by(year=int(year_filter))
                
                invoices = query.order_by(BOPInvoice.year.desc()).all()
                
                for invoice in invoices:
                    # Calculate payment info
                    payments = Payment.query.filter_by(
                        business_invoice_id=invoice.id
                    ).all()
                    total_paid = sum(p.payment_amount for p in payments)
                    
                    results['found'].append({
                        'type': 'Business',
                        'account_no': business.account_no,
                        'owner_name': business.business_name,
                        'invoice_no': invoice.invoice_no,
                        'invoice_id': invoice.id,
                        'year': invoice.year,
                        'amount': invoice.total_amount or invoice.amount,
                        'paid': total_paid,
                        'status': invoice.status
                    })
        
        # Find accounts that weren't found
        found_accounts = {item['account_no'] for item in results['found']}
        results['not_found'] = [acc for acc in account_numbers if acc not in found_accounts]
        
    except Exception as e:
        app.logger.error(f'Error in batch print preview: {str(e)}')
        flash(f'Error loading invoices: {str(e)}', 'error')
        return redirect(url_for('batch_print'))
    
    return render_template('batch_print_preview.html', results=results)


@app.route('/batch-print/execute')
@login_required
def batch_print_execute():
    """Execute batch printing - generate combined print view"""
    batch_data = session.get('batch_print_data')
    
    if not batch_data:
        flash('No batch print data found', 'error')
        return redirect(url_for('batch_print'))
    
    invoice_type = batch_data['invoice_type']
    account_numbers = batch_data['account_numbers']
    year_filter = batch_data.get('year_filter')
    
    invoices_data = []
    
    try:
        if invoice_type in ['Property', 'ALL']:
            # Get property invoices
            properties = Property.query.filter(
                Property.account_no.in_(account_numbers)
            ).all()
            
            for prop in properties:
                query = PropertyInvoice.query.filter_by(property_id=prop.id)
                if year_filter:
                    query = query.filter_by(year=int(year_filter))
                
                invoices = query.order_by(PropertyInvoice.year.desc()).all()
                
                for invoice in invoices:
                    # Get payments
                    payments = Payment.query.filter_by(
                        property_invoice_id=invoice.id
                    ).all()
                    total_paid = sum(p.payment_amount for p in payments)
                    
                    # Calculate arrears
                    previous_invoices = PropertyInvoice.query.filter(
                        PropertyInvoice.property_id == prop.id,
                        PropertyInvoice.year < invoice.year
                    ).all()
                    
                    total_arrears = 0.0
                    arrears_breakdown = []
                    
                    for prev_invoice in previous_invoices:
                        prev_total = prev_invoice.total_amount or prev_invoice.amount
                        prev_payments = Payment.query.filter_by(
                            property_invoice_id=prev_invoice.id
                        ).all()
                        prev_paid = sum(p.payment_amount for p in prev_payments)
                        prev_balance = prev_total - prev_paid
                        
                        if prev_balance > 0:
                            total_arrears += prev_balance
                            arrears_breakdown.append({
                                'year': prev_invoice.year,
                                'invoice_no': prev_invoice.invoice_no,
                                'total': prev_total,
                                'paid': prev_paid,
                                'balance': prev_balance
                            })
                    
                    invoices_data.append({
                        'type': 'Property',
                        'invoice': invoice,
                        'entity': prop,
                        'total_paid': total_paid,
                        'total_arrears': total_arrears,
                        'arrears_breakdown': arrears_breakdown
                    })
        
        if invoice_type in ['BOP', 'ALL']:
            # Get business invoices
            businesses = BusinessOccupant.query.filter(
                BusinessOccupant.account_no.in_(account_numbers)
            ).all()
            
            for business in businesses:
                query = BOPInvoice.query.filter_by(business_id=business.id)
                if year_filter:
                    query = query.filter_by(year=int(year_filter))
                
                invoices = query.order_by(BOPInvoice.year.desc()).all()
                
                for invoice in invoices:
                    # Get payments
                    payments = Payment.query.filter_by(
                        business_invoice_id=invoice.id
                    ).all()
                    total_paid = sum(p.payment_amount for p in payments)
                    
                    # Calculate arrears
                    previous_invoices = BOPInvoice.query.filter(
                        BOPInvoice.business_id == business.id,
                        BOPInvoice.year < invoice.year
                    ).all()
                    
                    total_arrears = 0.0
                    arrears_breakdown = []
                    
                    for prev_invoice in previous_invoices:
                        prev_total = prev_invoice.total_amount or prev_invoice.amount
                        prev_payments = Payment.query.filter_by(
                            business_invoice_id=prev_invoice.id
                        ).all()
                        prev_paid = sum(p.payment_amount for p in prev_payments)
                        prev_balance = prev_total - prev_paid
                        
                        if prev_balance > 0:
                            total_arrears += prev_balance
                            arrears_breakdown.append({
                                'year': prev_invoice.year,
                                'invoice_no': prev_invoice.invoice_no,
                                'total': prev_total,
                                'paid': prev_paid,
                                'balance': prev_balance
                            })
                    
                    invoices_data.append({
                        'type': 'Business',
                        'invoice': invoice,
                        'entity': business,
                        'total_paid': total_paid,
                        'total_arrears': total_arrears,
                        'arrears_breakdown': arrears_breakdown
                    })
        
        log_action('Batch print executed', 
                  details=f'Printed {len(invoices_data)} invoices')
        
        return render_template('batch_print_execute.html', 
                             invoices_data=invoices_data,
                             invoice_type=invoice_type)
        
    except Exception as e:
        app.logger.error(f'Error executing batch print: {str(e)}')
        flash(f'Error generating print view: {str(e)}', 'error')
        return redirect(url_for('batch_print'))

# ==================== CLI Commands ====================
@app.cli.command()
def create_admin():
    """Create an admin user"""
    username = input('Enter username: ')
    email = input('Enter email: ')
    password = input('Enter password: ')
    
    with app.app_context():  # The application context starts here
        if User.query.filter_by(username=username).first():
            print('Username already exists')
            return
    
        user = User(username=username, email=email, role='admin')
        user.set_password(password)
        db.session.add(user)
        
        #  FIX: This line must be inside the app.app_context() block.
        db.session.commit()
    
    print(f'Admin user "{username}" created successfully.')
    
@app.cli.command()
def fix_user_timestamps():
    """Fix users with NULL created_at timestamps"""
    from datetime import datetime
    
    with app.app_context():
        users_without_timestamp = User.query.filter(User.created_at.is_(None)).all()
        
        if not users_without_timestamp:
            print('All users have timestamps!')
            return
        
        print(f'Found {len(users_without_timestamp)} users without timestamps')
        
        for user in users_without_timestamp:
            user.created_at = datetime.utcnow()
            print(f'Fixed timestamp for user: {user.username}')
        
        db.session.commit()
        print(f'✓ Fixed {len(users_without_timestamp)} users')    
    # The context ends here

# ==================== Main ====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create default admin if no users exist
        if User.query.count() == 0:
            admin = User(
                username='admin', 
                email='admin@example.com', 
                phone_number='0000000000',  #  ADD THIS LINE
                role='admin',
                is_temp_password=False  #  ADD THIS LINE (admin doesn't need to reset password)
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('Default admin user created: username=admin, password=admin123')
    
    app.run(debug=True)