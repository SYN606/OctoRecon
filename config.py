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

TIMEOUT = 15
VERIFY_SSL = True
FOLLOW_REDIRECTS = True

USER_AGENT = (
    "OctoRecon/1.0 "
    "(Passive Recon Framework)"
)

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