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

Open `.env` in your text editor and add your free API keys for Shodan, AlienVault, SecurityTrails, etc.

---

## 💻 Usage

### Launch the Web Dashboard (Recommended)
Provides a beautiful hacker-themed UI to scan targets, inspect the interactive DNSDumpster-style infrastructure graph, export JSON reports, and read old reports offline.
```bash
python octorecon.py web
```
*Access the dashboard at: `http://127.0.0.1:8000`*

### CLI Mode

**DNS Intelligence & Infrastructure Mapping (DNSDumpster Style):**
```bash
# Full DNS record and security audit
python octorecon.py dns example.com

# Include passive subdomain enumeration and display infrastructure graph tree
python octorecon.py dns example.com --subdomains --graph

# Export full DNS intelligence report and graph relationships to JSON
python octorecon.py dns example.com --subdomains --export example_dns.json
```

**Run a full concurrent scan against a target:**
```bash
python octorecon.py scan https://example.com
```

**Run specific modules only:**
```bash
python octorecon.py scan https://example.com -m "DNS, Firewall / WAF Detection, Shodan Intelligence"
```

**List all available modules:**
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
