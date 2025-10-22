# settings.py

import os
import logging
from logging.handlers import RotatingFileHandler
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# ---------------- Load Environment Variables ----------------
load_dotenv()  # loads .env file

# Flask / App Secret
FLASK_SECRET = os.getenv("FLASK_SECRET", "supersecretkey")

# ---------------- Database Settings ----------------
DB_SERVER = os.getenv("DB_SERVER", "localhost")
DB_NAME = os.getenv("DB_NAME", "ZoomCallerID")
DB_USERNAME = os.getenv("DB_USERNAME", "sa")
DB_PASSWORD = os.getenv("DB_PASSWORD", "yourStrong(!)Password")
DB_DRIVER = os.getenv("DB_DRIVER", "ODBC Driver 18 for SQL Server")

# SQLAlchemy Connection String
DB_CONNECTION_STRING = (
    f"mssql+pyodbc://{DB_USERNAME}:{DB_PASSWORD}@{DB_SERVER}/{DB_NAME}"
    f"?driver={DB_DRIVER.replace(' ', '+')}"
)

# Create engine & session
engine = create_engine(DB_CONNECTION_STRING, fast_executemany=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ---------------- Logging Settings ----------------
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "app.log")

logger = logging.getLogger("zoom_app")
logger.setLevel(logging.INFO)

# Rotating file handler
handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] %(name)s - %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# Optional: also log to console
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

logger.info("Settings loaded successfully.")



