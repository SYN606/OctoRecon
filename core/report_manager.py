"""
Report Manager
Author : 0ct0pu3
VERSION : 1.0.0
"""

import json
import shutil
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from config import REPORT_DIR


class ReportManager:

    def __init__(self):

        self.report = {
            "tool": "OctoRecon",
            "version": "1.0.0",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": "",
            "modules": {},
            "summary": {},
        }

    def set_target(self, target):

        self.report["target"] = target

    def add_module(self, name, data):

        self.report["modules"][name] = data

    def set_summary(self, summary):
        """
        Backward compatibility.
        Summary is calculated automatically now.
        """
        self.report["summary"] = summary

    def calculate_summary(self):

        total_score = 0
        total_max = 0

        for module in self.report["modules"].values():

            total_score += module.get("score", 0)
            total_max += module.get("max_score", 0)

        percentage = 0

        if total_max:
            percentage = round(
                (total_score / total_max) * 100,
                2,
            )

        if percentage >= 90:
            grade = "A+"
        elif percentage >= 80:
            grade = "A"
        elif percentage >= 70:
            grade = "B"
        elif percentage >= 60:
            grade = "C"
        elif percentage >= 50:
            grade = "D"
        else:
            grade = "F"

        self.report["summary"] = {
            "score": total_score,
            "maximum": total_max,
            "percentage": percentage,
            "grade": grade,
        }

    def _get_filename(self):

        target = (
            self.report["target"]
            .replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        return f"{target}_{timestamp}"

    def save_json(self):

        self.calculate_summary()

        filename = self._get_filename() + ".json"

        REPORT_DIR.mkdir(parents=True, exist_ok=True)

        path = REPORT_DIR / filename

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.report,
                file,
                indent=4,
                ensure_ascii=False,
            )

        return path

    def save_html(self):

        self.calculate_summary()

        REPORT_DIR.mkdir(parents=True, exist_ok=True)

        filename = self._get_filename() + ".html"

        report_path = REPORT_DIR / filename

        project_root = Path(__file__).resolve().parent.parent

        template_dir = project_root / "templates"

        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True,
        )

        template = env.get_template("report.html")

        html = template.render(
            report=self.report
        )

        with open(
            report_path,
            "w",
            encoding="utf-8",
        ) as file:

            file.write(html)

        # ==========================================
        # Copy CSS
        # ==========================================

        css_source = template_dir / "style.css"
        css_destination = REPORT_DIR / "style.css"

        if css_source.exists():
            shutil.copy2(
                css_source,
                css_destination,
            )

        # ==========================================
        # Copy JS
        # ==========================================

        js_source = template_dir / "report.js"
        js_destination = REPORT_DIR / "report.js"

        if js_source.exists():
            shutil.copy2(
                js_source,
                js_destination,
            )

        # ==========================================
        # Copy Assets Folder
        # ==========================================

        assets_source = template_dir / "assets"
        assets_destination = REPORT_DIR / "assets"

        if assets_source.exists():

            if assets_destination.exists():
                shutil.rmtree(assets_destination)

            shutil.copytree(
                assets_source,
                assets_destination,
            )

        return report_path
    
    # ==========================================================
    # Export Report (CLI + Web)
    # ==========================================================

    def export(self):

        self.calculate_summary()

        return self.report