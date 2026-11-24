import os

APP_NAME = "DriftRadar"
APP_VERSION = "1.0.0"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./driftradar.db")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
MIN_SAMPLES = int(os.getenv("MIN_SAMPLES", "20"))
PSI_THRESHOLD = float(os.getenv("PSI_THRESHOLD", "0.20"))
KS_ALPHA = float(os.getenv("KS_ALPHA", "0.01"))
