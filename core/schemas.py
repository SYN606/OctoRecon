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
    modules: Dict[str, ModuleResult] = Field(default_factory=dict)

    def add_module(self, name: str, data: dict):
        """Legacy V1 method for modules that call scanner.report.add_module directly."""
        self.modules[name] = ModuleResult(
            module_name=name,
            score=data.get("score", 0),
            max_score=data.get("max_score", 20),
            description=data.get("description", ""),
            data=data.get("rows", []) or ([{"Content": data.get("content")}] if "content" in data else [])
        )

    def calculate_grade(self):
        self.total_score = sum(m.score for m in self.modules.values())
        self.max_potential_score = sum(m.max_score for m in self.modules.values())
        if self.max_potential_score == 0:
            return
        
        percentage = (self.total_score / self.max_potential_score) * 100
        if percentage >= 90: self.grade = "A+"
        elif percentage >= 80: self.grade = "A"
        elif percentage >= 70: self.grade = "B"
        elif percentage >= 60: self.grade = "C"
        elif percentage >= 50: self.grade = "D"
        else: self.grade = "F"
