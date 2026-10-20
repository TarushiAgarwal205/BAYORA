import os


HOST = os.environ.get("BAYORA_HOST", "127.0.0.1")
PORT = int(os.environ.get("BAYORA_PORT", "8000"))
APP_ENV = os.environ.get("APP_ENV", "development")
