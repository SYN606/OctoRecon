# 🐙 OctoRecon V2
**Modern Passive Intelligence & Web Reconnaissance Framework**

> *Developed by **octopus**, enhanced by **[SYN606](https://syn606.wtf)***

OctoRecon V2 is a high-speed, highly concurrent reconnaissance framework designed for penetration testers and security researchers. Upgraded with modern Python architectures (Asyncio, Pydantic, FastAPI), it executes 17+ intelligence modules simultaneously and outputs results beautifully to both the CLI and a sleek Web Dashboard.

## ✨ Key Features
- **V2 Concurrent Engine:** Blazing fast execution using Python 3.11+ `TaskGroup`.
- **Strict Data Schemas:** Powered by Pydantic for flawless report generation.
- **Web Dashboard:** A gorgeous, Tailwind-powered local UI with Report Export/Import capabilities.
- **OSINT Integrations:** Built-in support for Shodan, AlienVault, VirusTotal, and more.
- **Modular Design:** Drop new modules into `modules/` and they are auto-discovered instantly.

---

## 🚀 Quick Setup Guide

### 1. Prerequisites
- **Python 3.11+**

### 2. Installation
```powershell
# Clone the repository and navigate to the folder
git clone https://github.com/syn606/octorecon.git
cd OctoRecon

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration (API Keys)
To prevent rate-limiting (429 errors) and unlock deep OSINT scanning (like Shodan), you must configure your API keys:

```powershell
# Copy the template environment file (Windows)
Copy-Item example.env .env
```
```bash
# Copy the template environment file (Linux/Mac)
cp example.env .env
```

Open `.env` in your text editor and add your free API keys for Shodan, AlienVault, SecurityTrails, etc.

---

## 💻 Usage

### Launch the Web Dashboard (Recommended)
Provides a beautiful hacker-themed UI to scan targets, export JSON reports, and read old reports offline.
```bash
python octorecon.py web
```
*Access the dashboard at: `http://127.0.0.1:8000`*

### CLI Mode

**List all available modules:**
```bash
python octorecon.py list-modules
```

**Run a full concurrent scan against a target:**
```bash
python octorecon.py scan https://example.com
```

**Run specific modules only:**
```bash
python octorecon.py scan https://example.com -m "Broken Links, DNS, Shodan Intelligence"
```

---

## 📚 Modules Included
- **Web:** Broken Links, Cookies, HTTP Methods, Redirects, Content Security Policy (CSP)
- **Core:** DNS, SSL, Technology Detection, WHOIS
- **Passive:** Emails, Javascript, Robots.txt, Security.txt, Sitemap, Subdomains, Wayback Machine, Shodan Intelligence

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
