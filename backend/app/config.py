import os

class Settings:
    PROJECT_NAME: str = "SiteCure - Web Vulnerability Scanner"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./sitecure.db")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT_SECONDS: int = 300

settings = Settings()
