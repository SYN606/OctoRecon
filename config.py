"""
Configuration for OctoRecon V2
Author : 0ct0pu3, SYN606
VERSION : 2.0.0
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Project Information
APP_NAME = "OctoRecon"
VERSION = "2.0.0"
AUTHOR = ["0ct0pu3", "SYN606"]

# Directories
BASE_DIR = Path(__file__).resolve().parent

REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"
DATABASE_DIR = BASE_DIR / "database"

REPORT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
DATABASE_DIR.mkdir(exist_ok=True)

# Load .env file
load_dotenv()

# --- HTTP Core Client Configuration ---
TIMEOUT = int(os.getenv("OCTORECON_TIMEOUT", 15))
MAX_CONCURRENT = int(os.getenv("OCTORECON_MAX_CONCURRENT", 50))
VERIFY_SSL = os.getenv("OCTORECON_VERIFY_SSL", "True").lower() == "true"
FOLLOW_REDIRECTS = os.getenv("OCTORECON_FOLLOW_REDIRECTS", "True").lower() == "true"
USER_AGENT = os.getenv("OCTORECON_USER_AGENT", "OctoRecon-Modern/2.0")

# --- Database Configuration ---
DB_PATH = Path(os.getenv("OCTORECON_DB_PATH", str(DATABASE_DIR / "octorecon.db")))

# --- Web Server Configuration ---
WEB_HOST = os.getenv("OCTORECON_HOST", "127.0.0.1")
WEB_PORT = int(os.getenv("OCTORECON_PORT", 8000))

# --- OSINT & Reconnaissance API Keys (V2 Active) ---
# Shodan: Used in Shodan Intelligence module for ports, banners, and CVEs
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# IPInfo: Used in Server Location module for geolocation, ASN, and hosting details
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

# AlienVault OTX: Used in Subdomains module for passive DNS queries without 429 rate-limiting
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")

# URLScan: Used in Subdomains module for passive domain search
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

# --- Module Specific Defaults ---
BROKEN_LINK_TIMEOUT = 10
MAX_REDIRECTS = 10
MAX_LINKS = 500

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
