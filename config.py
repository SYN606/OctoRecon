"""
Configuration
Author : 0ct0pu3
VERSION : 1.0.0
"""

from pathlib import Path

# ===============================
# Project Information
# ===============================

APP_NAME = "OctoRecon"
VERSION = "1.0.0"
AUTHOR = "0ct0pu3"

# ===============================
# Directories
# ===============================

BASE_DIR = Path(__file__).resolve().parent

REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"
DATABASE_DIR = BASE_DIR / "database"

REPORT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
DATABASE_DIR.mkdir(exist_ok=True)

# ===============================
# HTTP Configuration
# ===============================
import os
from dotenv import load_dotenv

load_dotenv()

TIMEOUT = int(os.getenv("OCTORECON_TIMEOUT", 15))
VERIFY_SSL = os.getenv("OCTORECON_VERIFY_SSL", "True").lower() == "true"
FOLLOW_REDIRECTS = os.getenv("OCTORECON_FOLLOW_REDIRECTS", "True").lower() == "true"

USER_AGENT = os.getenv("OCTORECON_USER_AGENT", "OctoRecon/1.0 (Passive Recon Framework)")

# ===============================
# API Keys (Loaded from .env)
# ===============================
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# ===============================
# Broken Link Scanner
# ===============================

BROKEN_LINK_TIMEOUT = 10
MAX_REDIRECTS = 10
MAX_LINKS = 500

# ===============================
# Security Header Score
# ===============================

SECURITY_HEADERS = {
    "Content-Security-Policy": 15,
    "Strict-Transport-Security": 15,
    "X-Frame-Options": 10,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10,
    "Cross-Origin-Embedder-Policy": 10,
    "Cross-Origin-Opener-Policy": 10,
    "Cross-Origin-Resource-Policy": 10,
}