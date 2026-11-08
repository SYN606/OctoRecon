from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, HttpUrl, Field, model_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    title: str
    severity: Severity = Severity.INFO
    description: str = ""


class ModuleResult(BaseModel):
    module_name: str = ""
    category: str = "General"
    score: int = Field(default=0, ge=0, le=100)
    max_score: int = 20
    description: str = ""
    findings: List[Finding] = Field(default_factory=list)
    data: List[Any] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def normalize_fields(cls, values: Any) -> Any:
        if isinstance(values, dict):
            if "name" in values and not values.get("module_name"):
                values["module_name"] = values["name"]
            if "summary" in values and not values.get("description"):
                values["description"] = values["summary"]
            
            raw_data = values.get("data")
            if isinstance(raw_data, dict):
                if "score" in raw_data and "score" not in values:
                    values["score"] = raw_data["score"]
                if "max_score" in raw_data and "max_score" not in values:
                    values["max_score"] = raw_data["max_score"]

                if "rows" in raw_data and isinstance(raw_data["rows"], list):
                    values["data"] = raw_data["rows"]
                else:
                    values["data"] = [{"Property": str(k), "Value": str(v)} for k, v in raw_data.items()]
            elif raw_data is None:
                values["data"] = []
        return values


class FinalReport(BaseModel):
    tool: str = "OctoRecon v2 (Modern)"
    scan_time: datetime = Field(default_factory=datetime.now)
    target: str
    total_score: int = 0
    max_potential_score: int = 0
    grade: str = "N/A"
    grading_notes: str = ""
    modules: Dict[str, ModuleResult] = Field(default_factory=dict)
    infrastructure_graph: Dict[str, Any] = Field(default_factory=dict)

    def add_module(self, name: str, data: dict):
        """Legacy V1 method for modules that call scanner.report.add_module directly."""
        raw_data = data.get("rows", [])
        if not raw_data and "data" in data and isinstance(data["data"], dict):
            raw_data = [{"Property": k, "Value": str(v)} for k, v in data["data"].items()]
        elif not raw_data and "items" in data and isinstance(data["items"], list):
            raw_data = [{"Item": str(item)} for item in data["items"]]
        elif not raw_data and "content" in data:
            raw_data = [{"Content": data.get("content")}]

        self.modules[name] = ModuleResult(
            module_name=name,
            score=data.get("score", 0),
            max_score=data.get("max_score", 20),
            description=data.get("description", ""),
            data=raw_data
        )

    def calculate_grade(self):
        """
        Industry-standard Deductive Security Posture Grading Engine
        (Inspired by Mozilla Observatory, SSL Labs, and OWASP ASVS).
        
        Separates Security Audit modules from Reconnaissance/OSINT asset discovery,
        evaluates verified Findings by Severity, and applies defensive posture caps.
        """
        if not self.modules:
            self.grade = "N/A"
            self.total_score = 0
            self.max_potential_score = 100
            return

        # Security Posture Audit Modules vs Inventory/Recon Modules
        AUDIT_MODULES = {
            "SSL",
            "Headers",
            "Content Security Policy",
            "Cookies",
            "DNS",
            "HTTP Methods",
            "Redirects",
            "Firewall / WAF Detection",
            "Technology",
            "securitytxt",
        }

        audit_modules_run = [m for name, m in self.modules.items() if name in AUDIT_MODULES]

        if not audit_modules_run:
            # Only recon/inventory modules (e.g. subdomains, whois, wayback) were executed
            self.total_score = 100
            self.max_potential_score = 100
            self.grade = "N/A"
            self.grading_notes = "Informational recon scan only; security posture grade requires security audit modules."
            return

        # 1. Base Score starts at 100 (Full Security Baseline)
        MODULE_DEDUCTION_CAPS = {
            "SSL": 40,
            "Headers": 25,
            "Content Security Policy": 20,
            "Cookies": 15,
            "DNS": 15,
            "HTTP Methods": 15,
            "Redirects": 15,
            "Technology": 25,
            "Firewall / WAF Detection": 10,
            "securitytxt": 5,
        }

        total_deduction = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        # Collect unique findings and calculate module-bounded deductions
        seen_findings = set()
        critical_reasons = []
        high_reasons = []

        for name, module in self.modules.items():
            mod_deduction = 0
            for f in module.findings:
                # Deduplicate findings across modules
                key = (f.severity, f.title.strip().lower())
                if key in seen_findings:
                    continue
                seen_findings.add(key)

                if f.severity == Severity.CRITICAL:
                    critical_count += 1
                    mod_deduction += 35
                    critical_reasons.append(f.title)
                elif f.severity == Severity.HIGH:
                    high_count += 1
                    mod_deduction += 15
                    high_reasons.append(f.title)
                elif f.severity == Severity.MEDIUM:
                    medium_count += 1
                    mod_deduction += 6
                elif f.severity == Severity.LOW:
                    low_count += 1
                    mod_deduction += 2

            # Cap deductions per module category (Mozilla Observatory / SSL Labs standard)
            cap = MODULE_DEDUCTION_CAPS.get(name, 20)
            total_deduction += min(mod_deduction, cap)

        base_score = max(0, 100 - total_deduction)

        # 2. Defense-in-Depth Posture Bonuses (Max +10 bonus)
        bonus = 0
        waf_mod = self.modules.get("Firewall / WAF Detection")
        if waf_mod and waf_mod.score == 20:
            bonus += 5  # Verified active WAF protection

        dns_mod = self.modules.get("DNS")
        if dns_mod and any("DNSSEC Validated" in str(row) for row in dns_mod.data):
            bonus += 3  # Cryptographic DNSSEC assurance

        base_score = min(100, max(0, base_score + bonus))
        self.total_score = base_score
        self.max_potential_score = 100

        # 3. Granular Percentage-to-Grade Scale
        if base_score >= 95: self.grade = "A+"
        elif base_score >= 90: self.grade = "A"
        elif base_score >= 85: self.grade = "A-"
        elif base_score >= 80: self.grade = "B+"
        elif base_score >= 75: self.grade = "B"
        elif base_score >= 70: self.grade = "B-"
        elif base_score >= 65: self.grade = "C+"
        elif base_score >= 60: self.grade = "C"
        elif base_score >= 55: self.grade = "C-"
        elif base_score >= 45: self.grade = "D"
        else: self.grade = "F"

        # 4. Strict Severity Caps (SSL Labs & Mozilla Observatory Style)
        # A website with critical/high security issues cannot receive a passing A/B grade.
        notes = []
        if critical_count > 0:
            self.grade = "F"
            notes.append(f"Grade capped at F due to {critical_count} CRITICAL finding(s): {', '.join(critical_reasons[:2])}")
        elif high_count > 0:
            if self.grade in ("A+", "A", "A-", "B+", "B", "B-"):
                self.grade = "C"
                notes.append(f"Grade capped at C due to {high_count} HIGH severity finding(s): {', '.join(high_reasons[:2])}")
        elif medium_count > 0:
            if self.grade in ("A+", "A", "A-"):
                self.grade = "B"
                notes.append(f"Grade capped at B due to {medium_count} MEDIUM severity finding(s).")

        if bonus > 0 and critical_count == 0:
            notes.append(f"+{bonus} defense-in-depth posture bonus applied.")

        self.grading_notes = " | ".join(notes) if notes else "All security posture checks passed cleanly."
