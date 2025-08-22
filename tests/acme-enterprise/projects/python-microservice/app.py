#!/usr/bin/env python3
"""
ACME Enterprise Python Microservice
A vulnerable Flask application for testing Typosentinel detection capabilities.

This application intentionally contains security vulnerabilities for testing purposes.
DO NOT use in production environments.
"""

import os
import sys
import json
import hashlib
import secrets
import sqlite3
import subprocess
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Any

import bcrypt
import jwt
import redis
import requests
from flask import Flask, request, jsonify, session, g, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from marshmallow import Schema, fields, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging
from logging.handlers import RotatingFileHandler

# Vulnerable imports (for testing)
import pickle  # Dangerous for deserialization
import yaml  # Can be vulnerable to code injection
import xml.etree.ElementTree as ET  # Vulnerable to XXE
from subprocess import call  # Command injection risk

# Initialize Flask app
app = Flask(__name__)

# Configuration (vulnerable - hardcoded secrets)
app.config['SECRET_KEY'] = 'acme-super-secret-key-2023-vulnerable'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-never-change-this'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///acme_microservice.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'  # Vulnerable path
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app, origins="*")  # Vulnerable CORS configuration

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)

# Redis connection (vulnerable - no authentication)
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
except:
    redis_client = None

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if not app.debug:
    file_handler = RotatingFileHandler('logs/microservice.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')
    api_key = db.Column(db.String(64), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self):
        self.api_key = secrets.token_urlsafe(32)
        return self.api_key
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active
        }

class Package(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(20), nullable=False)
    registry = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    author = db.Column(db.String(100))
    license = db.Column(db.String(50))
    downloads = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)
    vulnerabilities = db.Column(db.Text)  # JSON string
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'version': self.version,
            'registry': self.registry,
            'description': self.description,
            'author': self.author,
            'license': self.license,
            'downloads': self.downloads,
            'risk_score': self.risk_score,
            'vulnerabilities': json.loads(self.vulnerabilities) if self.vulnerabilities else [],
            'scan_timestamp': self.scan_timestamp.isoformat()
        }

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    threats_detected = db.Column(db.Text)  # JSON string
    confidence_score = db.Column(db.Float, default=0.0)
    scan_duration = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'package_id': self.package_id,
            'user_id': self.user_id,
            'scan_type': self.scan_type,
            'threats_detected': json.loads(self.threats_detected) if self.threats_detected else [],
            'confidence_score': self.confidence_score,
            'scan_duration': self.scan_duration,
            'created_at': self.created_at.isoformat()
        }

# Marshmallow Schemas
class UserSchema(Schema):
    username = fields.Str(required=True, validate=lambda x: len(x) >= 3)
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=lambda x: len(x) >= 6)
    role = fields.Str(missing='user')

class PackageSchema(Schema):
    name = fields.Str(required=True)
    version = fields.Str(required=True)
    registry = fields.Str(required=True)
    description = fields.Str(missing='')
    author = fields.Str(missing='')
    license = fields.Str(missing='')

class ScanSchema(Schema):
    package_name = fields.Str(required=True)
    package_version = fields.Str(missing='latest')
    registry = fields.Str(missing='npm')
    scan_type = fields.Str(missing='full')

# Authentication decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key is missing'}), 401
        
        # Vulnerable: Direct database query without proper validation
        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Utility functions
def log_security_event(event_type: str, user_id: int, details: str):
    """Log security events (vulnerable - logs sensitive data)"""
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"{timestamp} - {event_type} - User {user_id} - {details}"
    logger.warning(log_entry)
    
    # Vulnerable: Store in Redis without encryption
    if redis_client:
        redis_client.lpush('security_events', log_entry)
        redis_client.ltrim('security_events', 0, 999)  # Keep last 1000 events

def simulate_package_scan(package_name: str, version: str, registry: str) -> Dict[str, Any]:
    """Simulate package scanning with threat detection"""
    threats = []
    risk_score = 0.0
    
    # Simulate typosquatting detection
    suspicious_patterns = [
        'lodash-utils', 'express-utils', 'requets', 'beautifulsoup5',
        'numpy-extra', 'pandas-helper', 'flask-security', 'django-auth'
    ]
    
    if any(pattern in package_name.lower() for pattern in suspicious_patterns):
        threats.append({
            'type': 'typosquatting',
            'severity': 'high',
            'description': f'Package name "{package_name}" appears to be typosquatting a popular package',
            'confidence': 0.9
        })
        risk_score += 0.8
    
    # Simulate malware detection
    if 'malware' in package_name.lower() or 'backdoor' in package_name.lower():
        threats.append({
            'type': 'malware',
            'severity': 'critical',
            'description': 'Potential malware detected in package',
            'confidence': 0.95
        })
        risk_score += 0.9
    
    # Simulate dependency confusion
    if package_name.startswith('acme-') or package_name.startswith('internal-'):
        threats.append({
            'type': 'dependency_confusion',
            'severity': 'medium',
            'description': 'Potential dependency confusion attack',
            'confidence': 0.7
        })
        risk_score += 0.6
    
    return {
        'threats': threats,
        'risk_score': min(risk_score, 1.0),
        'scan_duration': 0.5 + (len(package_name) * 0.01)  # Simulate scan time
    }

# Routes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'service': 'acme-python-microservice'
    })

@app.route('/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """User registration endpoint"""
    try:
        schema = UserSchema()
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    # Create new user
    user = User(
        username=data['username'],
        email=data['email'],
        role=data.get('role', 'user')
    )
    user.set_password(data['password'])
    user.generate_api_key()
    
    db.session.add(user)
    db.session.commit()
    
    log_security_event('USER_REGISTERED', user.id, f'New user: {user.username}')
    
    return jsonify({
        'message': 'User registered successfully',
        'user': user.to_dict(),
        'api_key': user.api_key
    }), 201

@app.route('/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """User login endpoint"""
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    # Vulnerable: SQL injection possibility if using raw queries
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        log_security_event('LOGIN_FAILED', 0, f'Failed login attempt for: {data["username"]}')
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 401
    
    # Create JWT token
    token = jwt.encode({
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    log_security_event('LOGIN_SUCCESS', user.id, f'User logged in: {user.username}')
    
    return jsonify({
        'token': token,
        'user': user.to_dict()
    })

@app.route('/packages', methods=['GET'])
@token_required
def list_packages(current_user):
    """List packages with filtering and pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    registry = request.args.get('registry')
    search = request.args.get('search')
    
    query = Package.query
    
    if registry:
        query = query.filter(Package.registry == registry)
    
    if search:
        # Vulnerable: Potential SQL injection if not using ORM properly
        query = query.filter(
            Package.name.contains(search) |
            Package.description.contains(search)
        )
    
    packages = query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'packages': [pkg.to_dict() for pkg in packages.items],
        'total': packages.total,
        'pages': packages.pages,
        'current_page': page,
        'per_page': per_page
    })

@app.route('/packages/<int:package_id>', methods=['GET'])
@token_required
def get_package(current_user, package_id):
    """Get package details"""
    package = Package.query.get_or_404(package_id)
    return jsonify(package.to_dict())

@app.route('/scan/package', methods=['POST'])
@api_key_required
@limiter.limit("100 per hour")
def scan_package(current_user):
    """Scan a package for threats"""
    try:
        schema = ScanSchema()
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    package_name = data['package_name']
    package_version = data['package_version']
    registry = data['registry']
    scan_type = data['scan_type']
    
    # Check if package already exists
    package = Package.query.filter_by(
        name=package_name,
        version=package_version,
        registry=registry
    ).first()
    
    if not package:
        # Create new package entry
        package = Package(
            name=package_name,
            version=package_version,
            registry=registry,
            description=f'Package {package_name} from {registry}'
        )
        db.session.add(package)
        db.session.commit()
    
    # Perform scan simulation
    scan_results = simulate_package_scan(package_name, package_version, registry)
    
    # Update package risk score
    package.risk_score = scan_results['risk_score']
    package.vulnerabilities = json.dumps(scan_results['threats'])
    package.scan_timestamp = datetime.utcnow()
    
    # Create scan result record
    scan_result = ScanResult(
        package_id=package.id,
        user_id=current_user.id,
        scan_type=scan_type,
        threats_detected=json.dumps(scan_results['threats']),
        confidence_score=max([t.get('confidence', 0) for t in scan_results['threats']] + [0]),
        scan_duration=scan_results['scan_duration']
    )
    
    db.session.add(scan_result)
    db.session.commit()
    
    log_security_event('PACKAGE_SCANNED', current_user.id, 
                      f'Scanned {package_name}@{package_version} - Risk: {scan_results["risk_score"]}')
    
    return jsonify({
        'scan_id': scan_result.id,
        'package': package.to_dict(),
        'scan_results': scan_result.to_dict(),
        'summary': {
            'threats_found': len(scan_results['threats']),
            'risk_score': scan_results['risk_score'],
            'scan_duration': scan_results['scan_duration']
        }
    })

@app.route('/upload/package', methods=['POST'])
@token_required
@limiter.limit("10 per hour")
def upload_package(current_user):
    """Upload package file for analysis (vulnerable)"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Vulnerable: No file type validation
    filename = secure_filename(file.filename)
    
    # Vulnerable: Predictable upload path
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Create upload directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Save file (vulnerable to path traversal)
    file.save(upload_path)
    
    # Vulnerable: Execute file analysis without proper sandboxing
    try:
        # Simulate file analysis
        file_size = os.path.getsize(upload_path)
        file_hash = hashlib.sha256(open(upload_path, 'rb').read()).hexdigest()
        
        analysis_result = {
            'filename': filename,
            'size': file_size,
            'hash': file_hash,
            'upload_time': datetime.utcnow().isoformat(),
            'analysis': {
                'suspicious': filename.endswith('.exe') or 'malware' in filename.lower(),
                'risk_score': 0.8 if 'suspicious' in filename.lower() else 0.1
            }
        }
        
        log_security_event('FILE_UPLOADED', current_user.id, f'Uploaded: {filename}')
        
        return jsonify(analysis_result)
    
    except Exception as e:
        logger.error(f'File analysis error: {str(e)}')
        return jsonify({'error': 'File analysis failed'}), 500

@app.route('/admin/users', methods=['GET'])
@token_required
@admin_required
def list_users(current_user):
    """List all users (admin only)"""
    users = User.query.all()
    return jsonify({
        'users': [user.to_dict() for user in users],
        'total': len(users)
    })

@app.route('/admin/scan-results', methods=['GET'])
@token_required
@admin_required
def list_scan_results(current_user):
    """List all scan results (admin only)"""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    
    scan_results = ScanResult.query.order_by(ScanResult.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'scan_results': [result.to_dict() for result in scan_results.items],
        'total': scan_results.total,
        'pages': scan_results.pages,
        'current_page': page
    })

@app.route('/debug/info', methods=['GET'])
def debug_info():
    """Debug endpoint (extremely vulnerable - should not exist in production)"""
    return jsonify({
        'environment': dict(os.environ),  # Exposes all environment variables
        'config': {
            'SECRET_KEY': app.config['SECRET_KEY'],
            'JWT_SECRET_KEY': app.config['JWT_SECRET_KEY'],
            'DATABASE_URI': app.config['SQLALCHEMY_DATABASE_URI']
        },
        'system_info': {
            'python_version': sys.version,
            'platform': sys.platform,
            'cwd': os.getcwd()
        }
    })

@app.route('/vulnerable/eval', methods=['POST'])
def vulnerable_eval():
    """Extremely vulnerable endpoint for testing (code injection)"""
    data = request.json
    if not data or 'code' not in data:
        return jsonify({'error': 'Code parameter required'}), 400
    
    try:
        # EXTREMELY DANGEROUS: Never do this in real applications
        result = eval(data['code'])
        return jsonify({'result': str(result)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/vulnerable/pickle', methods=['POST'])
def vulnerable_pickle():
    """Vulnerable pickle deserialization endpoint"""
    data = request.json
    if not data or 'pickle_data' not in data:
        return jsonify({'error': 'pickle_data parameter required'}), 400
    
    try:
        # Vulnerable: Pickle deserialization
        import base64
        pickle_bytes = base64.b64decode(data['pickle_data'])
        result = pickle.loads(pickle_bytes)
        return jsonify({'result': str(result)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/vulnerable/xml', methods=['POST'])
def vulnerable_xml():
    """Vulnerable XML parsing (XXE attack)"""
    xml_data = request.data
    if not xml_data:
        return jsonify({'error': 'XML data required'}), 400
    
    try:
        # Vulnerable: XML External Entity (XXE) attack
        root = ET.fromstring(xml_data)
        return jsonify({'parsed': ET.tostring(root, encoding='unicode')})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/vulnerable/command', methods=['POST'])
def vulnerable_command():
    """Vulnerable command execution endpoint"""
    data = request.json
    if not data or 'command' not in data:
        return jsonify({'error': 'Command parameter required'}), 400
    
    try:
        # EXTREMELY DANGEROUS: Command injection vulnerability
        result = subprocess.check_output(data['command'], shell=True, text=True)
        return jsonify({'output': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(ValidationError)
def validation_error(error):
    return jsonify({'errors': error.messages}), 400

# Database initialization
@app.before_first_request
def create_tables():
    """Create database tables and seed initial data"""
    db.create_all()
    
    # Create admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@acme.local',
            role='admin'
        )
        admin.set_password('admin123')
        admin.generate_api_key()
        db.session.add(admin)
    
    # Create test user if not exists
    test_user = User.query.filter_by(username='testuser').first()
    if not test_user:
        test_user = User(
            username='testuser',
            email='test@acme.local',
            role='user'
        )
        test_user.set_password('test123')
        test_user.generate_api_key()
        db.session.add(test_user)
    
    # Create sample packages
    sample_packages = [
        {
            'name': 'lodash',
            'version': '4.17.21',
            'registry': 'npm',
            'description': 'A modern JavaScript utility library',
            'author': 'John-David Dalton',
            'license': 'MIT',
            'downloads': 50000000,
            'risk_score': 0.1
        },
        {
            'name': 'lodash-utils',  # Suspicious package
            'version': '1.0.0',
            'registry': 'npm',
            'description': 'Utility functions for lodash (SUSPICIOUS)',
            'author': 'unknown',
            'license': 'MIT',
            'downloads': 100,
            'risk_score': 0.9
        },
        {
            'name': 'requests',
            'version': '2.31.0',
            'registry': 'pypi',
            'description': 'Python HTTP for Humans',
            'author': 'Kenneth Reitz',
            'license': 'Apache 2.0',
            'downloads': 100000000,
            'risk_score': 0.1
        },
        {
            'name': 'requets',  # Typosquatting
            'version': '1.0.0',
            'registry': 'pypi',
            'description': 'HTTP library (TYPOSQUATTING)',
            'author': 'unknown',
            'license': 'MIT',
            'downloads': 50,
            'risk_score': 0.95
        }
    ]
    
    for pkg_data in sample_packages:
        existing = Package.query.filter_by(
            name=pkg_data['name'],
            version=pkg_data['version'],
            registry=pkg_data['registry']
        ).first()
        
        if not existing:
            package = Package(**pkg_data)
            db.session.add(package)
    
    db.session.commit()
    logger.info('Database initialized with sample data')

if __name__ == '__main__':
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_ENV') == 'development'
    )