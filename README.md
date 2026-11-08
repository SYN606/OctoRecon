# 🐙 OctoRecon V2
**Modern Passive Intelligence & Web Reconnaissance Framework**

> *Developed by **octopus**, enhanced by **[SYN606](https://syn606.wtf)***

OctoRecon V2 is a high-speed, highly concurrent reconnaissance framework designed for penetration testers and security researchers. Upgraded with modern Python architectures (Asyncio, Pydantic, FastAPI), it executes 20+ intelligence modules simultaneously and outputs results beautifully to both the CLI and a sleek Web Dashboard with DNSDumpster-style interactive infrastructure mapping.

## ✨ Key Features
- **V2 Concurrent Engine:** Blazing fast execution using Python 3.11+ `TaskGroup`.
- **Advanced DNS Intelligence:** Comprehensive DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV, PTR, DS, DNSKEY, TLSA).
- **DNS Security & Hygiene:** Deep auditing of SPF mechanisms, DMARC policy enforcement, DNSSEC status, and dangling CNAME takeover heuristics.
- **Infrastructure Relationship Graph:** Interactive visual network mapping (Domains, Subdomains, IPs, Mail Servers, Nameservers, ASNs) powered by Cytoscape.js.
- **Firewall & WAF Detection:** Automated fingerprinting and active challenge probing for 15+ WAF/DDoS vendors (Cloudflare, AWS WAF, Akamai, F5, Imperva, etc.).
- **Web Dashboard:** A gorgeous, Tailwind-powered local UI with Report Export/Import capabilities.
- **OSINT Integrations:** Built-in support for Shodan, AlienVault, IPInfo, VirusTotal, and more.
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
To prevent rate-limiting (429 errors) and unlock deep OSINT scanning (like Shodan), configure your API keys:

```powershell
# Copy the template environment file (Windows)
Copy-Item example.env .env
```
```bash
# Copy the template environment file (Linux/Mac)
cp example.env .env
```

Open `.env` in your text editor and add your free API keys for Shodan, IPInfo, AlienVault, or URLScan if available.

---

## 💻 Usage

### Launch the Web Dashboard
Provides a sleek hacker-themed UI with real-time scan progress, live Cytoscape infrastructure graph, persistent scan history (SQLite), and one-click PDF, CSV, and JSON report exports.
```bash
python octorecon.py web
```
*Access the dashboard at: `http://127.0.0.1:8000`*

---

### CLI Mode

#### 1. Full Concurrent Scan
```bash
# Run all 20 modules concurrently
python octorecon.py scan https://example.com

# Enable active probing (WAF trigger probe & path brute-forcing)
python octorecon.py scan https://example.com --active

# Export report directly to JSON, PDF, and CSV
python octorecon.py scan https://example.com --export report.json --pdf report.pdf --csv report.csv
```

#### 2. Run Specific Modules
```bash
# Using module name, slug, or alias
python octorecon.py scan https://example.com -m "dns, ssl, tech, headers"
```

#### 3. Run Any Individual Module Directly
Every module has its own dedicated CLI command or can be invoked via `module`:
```bash
# Dedicated CLI commands:
python octorecon.py ssl https://example.com
python octorecon.py headers https://example.com
python octorecon.py cookies https://example.com
python octorecon.py tech https://example.com --active
python octorecon.py whois example.com
python octorecon.py broken-links https://example.com
python octorecon.py subdomains example.com
python octorecon.py firewall https://example.com
python octorecon.py emails https://example.com
python octorecon.py javascript https://example.com
python octorecon.py robots https://example.com
python octorecon.py sitemap https://example.com
python octorecon.py securitytxt https://example.com
python octorecon.py shodan example.com
python octorecon.py ipinfo example.com
python octorecon.py csp https://example.com
python octorecon.py methods https://example.com
python octorecon.py redirects https://example.com
python octorecon.py wayback example.com

# Generic dynamic module runner:
python octorecon.py module ssl example.com
python octorecon.py module tech https://example.com
```

#### 4. DNS Intelligence & Infrastructure Mapping
```bash
# Full DNS record and security audit
python octorecon.py dns example.com

# Include passive subdomain discovery and infrastructure graph tree
python octorecon.py dns example.com --subdomains --graph

# Export DNS report to JSON, PDF, or CSV
python octorecon.py dns example.com --subdomains --export example_dns.json --pdf example_dns.pdf
```

#### 5. Scan History & Database Queries
Every scan is automatically indexed in an embedded SQLite database (`database/octorecon.db`):
```bash
# View list of past scans
python octorecon.py history

# Inspect findings of a specific past scan
python octorecon.py show-scan 1

# Export a past scan from the database
python octorecon.py export 1 --pdf past_scan.pdf --csv past_scan.csv
```

#### 6. List All Modules & CLI Commands
```bash
python octorecon.py list-modules
```

---

## 📚 Modules Included (20 Total)
- **Web:** Broken Links, Cookies, HTTP Methods, Redirects
- **Core:** DNS (Advanced Records, PTR, SPF/DMARC/DNSSEC), SSL, Technology Detection, WHOIS
- **Security:** Content Security Policy (CSP), Firewall / WAF Detection
- **Passive:** Emails, Javascript, Server Location (IPInfo), Robots.txt, Security.txt, Shodan Intelligence, Sitemap, Subdomains (with PTR Reverse DNS), Wayback Machine

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
