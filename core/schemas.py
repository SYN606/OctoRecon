from pydantic import BaseModel, HttpUrl, Field
from typing import Any, Dict, List, Optional
from datetime import datetime

class ModuleResult(BaseModel):
    module_name: str
    score: int = Field(default=0, ge=0, le=100)
    max_score: int = 20
    description: str = ""
    data: List[Any] = Field(default_factory=list)

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
        # 1. Base Scores (Displayed in UI)
        self.total_score = sum(m.score for m in self.modules.values())
        self.max_potential_score = sum(m.max_score for m in self.modules.values())
        
        if self.max_potential_score == 0:
            return

        # 2. Weighted Scoring System (Affects final letter grade)
        total_weighted_score = 0
        total_weighted_max = 0
        has_critical_failure = False
        has_high_failure = False

        for name, module in self.modules.items():
            weight = 1.0
            
            # CRITICAL Modules (Multiplies impact by 3x)
            if name in ["SSL", "Content Security Policy", "Shodan Intelligence", "Technology", "Headers", "Firewall / WAF Detection"]:
                weight = 3.0
                if module.score < (module.max_score * 0.4): 
                    has_critical_failure = True
                    self.grading_notes = f"Critical security failure detected in {name}."
            
            # HIGH Modules (Multiplies impact by 2x)
            elif name in ["Cookies", "HTTP Methods", "DNS", "Redirects"]:
                weight = 2.0
                if module.score < (module.max_score * 0.4):
                    has_high_failure = True
                    if not self.grading_notes: 
                        self.grading_notes = f"High security warning detected in {name}."
            
            # PASSIVE/INFO Modules (Standard 1x weight)
            # e.g., Broken Links, Sitemap, Robots, Emails, etc.
            
            total_weighted_score += (module.score * weight)
            total_weighted_max += (module.max_score * weight)

        # 3. Calculate Percentage
        percentage = (total_weighted_score / total_weighted_max) * 100 if total_weighted_max > 0 else 0
        
        # 4. Granular Grading Scale (+ / -)
        if percentage >= 97: self.grade = "A+"
        elif percentage >= 93: self.grade = "A"
        elif percentage >= 90: self.grade = "A-"
        elif percentage >= 87: self.grade = "B+"
        elif percentage >= 83: self.grade = "B"
        elif percentage >= 80: self.grade = "B-"
        elif percentage >= 77: self.grade = "C+"
        elif percentage >= 73: self.grade = "C"
        elif percentage >= 70: self.grade = "C-"
        elif percentage >= 60: self.grade = "D"
        else: self.grade = "F"
        
        # 5. Severity Caps (Mozilla Observatory / SSL Labs style logic)
        # If a critical module completely fails (e.g., no SSL, high CVEs), cap the grade.
        if has_critical_failure and percentage >= 60:
            self.grade = "F"
            self.grading_notes += " Grade capped at F."
        elif has_high_failure and percentage >= 77:
            self.grade = "C"
            self.grading_notes += " Grade capped at C."
            
        if not self.grading_notes:
            self.grading_notes = "Target meets overall security baseline."
