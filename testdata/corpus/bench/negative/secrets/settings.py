# Benign configuration — secret-named keys with runtime injection, no literals.
import os

API_KEY = os.environ["API_KEY"]
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY")
DEBUG = False
ALLOWED_HOSTS = ["example.com", "www.example.com"]
