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
- **uv** (Extremely fast Python package installer recommended)

### 2. Installation
```powershell
# Clone the repository and navigate to the folder
git clone https://github.com/yourusername/octorecon.git
cd OctoRecon

# Install dependencies using uv
uv pip install -r requirements.txt
```

### 3. Environment Configuration (API Keys)
To prevent rate-limiting (429 errors) and unlock deep OSINT scanning (like Shodan), you must configure your API keys:

```powershell
# Copy the template environment file
Copy-Item example.env .env
```

Open `.env` in your text editor and add your free API keys for Shodan, AlienVault, SecurityTrails, etc.

---

## 💻 Usage

### Launch the Web Dashboard (Recommended)
Provides a beautiful hacker-themed UI to scan targets, export JSON reports, and read old reports offline.
```powershell
uv run octorecon.py web
```
*Access the dashboard at: `http://127.0.0.1:8000`*

### CLI Mode

**List all available modules:**
```powershell
uv run octorecon.py list-modules
```

**Run a full concurrent scan against a target:**
```powershell
uv run octorecon.py scan https://example.com
```

**Run specific modules only:**
```powershell
uv run octorecon.py scan https://example.com -m "Broken Links, DNS, Shodan Intelligence"
```

---

## 📚 Modules Included
- **Web:** Broken Links, Cookies, HTTP Methods, Redirects, Content Security Policy (CSP)
- **Core:** DNS, SSL, Technology Detection, WHOIS
- **Passive:** Emails, Javascript, Robots.txt, Security.txt, Sitemap, Subdomains, Wayback Machine, Shodan Intelligence

---

## 📄 License

**MIT License**

Copyright (c) 2026 octopus & SYN606

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
