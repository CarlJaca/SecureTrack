import os
from dotenv import load_dotenv

# Load .env file from project root
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))


class Config:
    """Application configuration loaded from environment variables."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'securetrack-secret-key-change-in-production')
    
    # MySQL Database
    MYSQL_HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
    MYSQL_DB = os.environ.get('MYSQL_DATABASE', 'securetrack')
    
    # Flask
    FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
    DEBUG = os.environ.get('FLASK_ENV', 'development') == 'development'
    
    # File upload
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SecureFiles')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max upload
