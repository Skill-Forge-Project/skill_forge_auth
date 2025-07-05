import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    
    # JWT settings
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_COOKIE_SECURE = False          # True in production (use HTTPS)
    JWT_COOKIE_HTTPONLY = False         # True in production (to prevent JavaScript access)
    JWT_COOKIE_SAMESITE = "Strict"
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=60)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    JWT_REFRESH_COOKIE_PATH = "/refresh_access_token"
    JWT_COOKIE_CSRF_PROTECT = False

