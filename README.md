<div align="center">

# 🐙 OctoRecon

**Passive Web Reconnaissance Framework**

*Fast • Modular • Async • Extensible*

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-v1.0.0-success?style=flat-square)](https://github.com/octopu3/OctoRecon/releases)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](#-contributing)

</div>

---

## 📖 About

## Overview

**OctoRecon** is a modern, modular, and extensible reconnaissance framework written in Python for collecting publicly available intelligence about web targets. It performs fully passive, non-intrusive reconnaissance by gathering information from HTTP responses, DNS records, SSL certificates, WHOIS data, public archives, search indexes, and other OSINT sources without exploiting or interacting aggressively with the target.

The framework is designed with a clean, module-based architecture, allowing new reconnaissance modules to be developed and integrated with minimal effort. Each module runs independently and contributes structured results to a unified console, HTML, and JSON reporting system.

OctoRecon helps security professionals quickly identify technologies, exposed assets, historical URLs, security headers, DNS information, SSL/TLS configurations, email addresses, JavaScript resources, robots.txt, sitemaps, subdomains, redirects, HTTP methods, and many other publicly accessible security insights.

Built for **Security Researchers**, **Bug Bounty Hunters**, And **Penetration Testers**, OctoRecon provides fast, reliable, and repeatable reconnaissance while remaining completely passive and safe for authorized security assessments.

> **Current Version:** `v1.0.0`

---

## 📑 Table of Contents

- [Features](#-features)
- [Modules](#-modules)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Sample Output](#-sample-output)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Disclaimer](#️-disclaimer)
- [License](#-license)
- [Author](#-author)

---

## ✨ Features

- ⚡ **Async scanning engine** — concurrent module execution for fast results
- 🧩 **Modular architecture** — every check is an independent, pluggable module
- 🎨 **Rich CLI output** — clean, readable terminal reporting powered by `rich`
- 🕵️ **100% passive reconnaissance** — no active exploitation, no target impact
- 📄 **JSON report generation** — machine-readable output for pipelines and tooling
- 🌐 **HTML report** — *machine-readable output for pipelines and tooling*
- 🔧 **Simple module development** — extend OctoRecon with your own checks in minutes
- 📊 **Web dashboard** — *coming soon*

---

## 📦 Modules

| Category    | Module                  | Description                                                       |
|-------------|------------------------ |-------------------------------------------------------------------|
| Core        | Headers                 | Analyze HTTP response headers and security headers.               |
| Core        | DNS                     | Retrieve DNS records and DNS configuration.                       |
| Core        | SSL/TLS                 | Inspect SSL certificates, issuer, validity, and protocol info.    |
| Core        | WHOIS                   | Collect domain registration and WHOIS information.                |
| Core        | Technology Detection    | Detect web technologies, frameworks, CMS, and web servers.        |
| Web         | Cookies                 | Analyze cookies and identify missing security attributes.         |
| Web         | Redirects               | Analyze HTTP redirects and redirect chains.                       |
| Web         | HTTP Methods            | Identify supported HTTP methods.                                  |
| Web         | Broken Links            | Check internal, external, and static resource links.              |
| Passive     | Robots.txt              | Retrieve and analyze the `robots.txt` file.                       |
| Passive     | Sitemap                 | Discover and analyze `sitemap.xml`.                               |
| Passive     | Wayback                 | Retrieve archived URLs from the Wayback Machine.                  |
| Passive     | JavaScript              | Discover and analyze external JavaScript resources.               |
| Passive     | Emails                  | Extract publicly exposed email addresses from web pages.          |
| Passive     | Subdomains              | Discover publicly available subdomains related to the target.     |
| Passive     | Security.txt            | Analyze RFC 9116 `security.txt` disclosure policy.                |
| Security    | Content Security Policy | Analyze Content-Security-Policy headers.                          |

---
> [!NOTE]
> Some modules depend on third-party OSINT services. Results may vary depending on target configuration, service availability, rate limiting, or regional restrictions. Temporary failures or incomplete results are expected in certain situations and do not necessarily indicate an issue with OctoRecon.

## 🚀 Installation

**1. Clone the repository**
```bash
git clone https://github.com/octopu3/OctoRecon.git
cd OctoRecon
```

**2. Create a virtual environment**
```bash
python -m venv .venv
```

**3. Activate it**

Windows:
```bash
.venv\Scripts\activate
```

Linux / macOS:
```bash
source .venv/bin/activate
```

**4. Install dependencies**
```bash
pip install -r requirements.txt
```

---

## ⚡ Usage

**Show help**
```bash
python octorecon.py -h
```

**Scan a target (all modules)**
```bash
python octorecon.py -u https://example.com
```

**Run a specific module**
```bash
python octorecon.py -u https://example.com -m headers
```

**Run multiple modules**
```bash
python octorecon.py -u https://example.com -m headers,dns
```

**List available modules**
```bash
python octorecon.py -l
```

---

## 📂 Project Structure

```text
OctoRecon/
│
├── core/            # Core scanning engine
├── modules/         # Individual recon modules
├── reports/         # Generated JSON/HTML reports
├── octorecon.py     # CLI entry point
├── requirements.txt # Python dependencies
└── README.md
```

---

## 🖥️ Sample Output

```text
$ python octorecon.py -u https://example.com -m headers,dns

[+] Target      : https://example.com
[+] Modules     : headers, dns
[+] Started     : 2026-07-20 14:32:10

[HEADERS] Missing Strict-Transport-Security header
[HEADERS] X-Frame-Options not set
[DNS]     A record   -> 93.184.216.34
[DNS]     MX record  -> not found

[+] Scan completed in 2.4s
[+] Report saved to reports/example.com_20260720.html
[+] Report saved to reports/example.com_20260720.json
```

## 📦 Creating a New Module

OctoRecon supports **automatic module discovery**.

Simply place a Python file anywhere inside the `modules/` directory (including subfolders), and it will be detected automatically at runtime.

No manual registration or configuration is required.

### Example

```text
modules/
├── headers.py
├── dns.py
├── passive/
│   ├── emails.py
│   ├── github.py
│   └── wayback.py
├── security/
│   ├── csp.py
│   └── clickjacking.py
```

After creating the file, the module will automatically appear in:

- `octorecon -l`
- CLI scans
- Reports

### Requirements

Every module must inherit from `BaseModule`.

```python
from core.base_module import BaseModule

class MyModule(BaseModule):

    name = "Example"
    slug = "example"
    category = "Passive"
    description = "Example module."

    async def run(self, scanner):
        ...
```

That's it. No changes to `modules/__init__.py` or any registry are required.

## 🤝 Contributing

Contributions, feature requests, and bug reports are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-module`)
3. Commit your changes (`git commit -m "Add amazing module"`)
4. Push to the branch (`git push origin feature/amazing-module`)
5. Open a Pull Request

Feel free to open an [Issue](https://github.com/octopu3/OctoRecon/issues) for bugs or ideas.

---

## ⚠️ Disclaimer

This tool is intended **for educational purposes and authorized security testing only**.
The author is not responsible for any misuse or damage caused by this software.
**Always obtain proper authorization before scanning any system.**

---

## 📄 License

Released under the [MIT License](LICENSE).

---

## 👨‍💻 Author

([@octopu3](https://github.com/octopu3))

---

<div align="center">

⭐ **If you find this project useful, consider giving it a Star!**

</div>
