"""
Report Schema Helpers
Author : 0ct0pu3
VERSION : 1.0.0

Provides a common schema for all report modules.
"""

from typing import Any, Dict, List, Optional


class Report:

    @staticmethod
    def table(
        title: str,
        columns: List[str],
        rows: List[Dict[str, Any]],
        score: int = 0,
        max_score: int = 0,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:

        return {
            "title": title,
            "type": "table",
            "description": description,
            "columns": columns,
            "rows": rows,
            "score": score,
            "max_score": max_score,
        }

    @staticmethod
    def keyvalue(
        title: str,
        data: Dict[str, Any],
        score: int = 0,
        max_score: int = 0,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:

        return {
            "title": title,
            "type": "keyvalue",
            "description": description,
            "data": data,
            "score": score,
            "max_score": max_score,
        }

    @staticmethod
    def list(
        title: str,
        items: List[Any],
        score: int = 0,
        max_score: int = 0,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:

        return {
            "title": title,
            "type": "list",
            "description": description,
            "items": items,
            "score": score,
            "max_score": max_score,
        }

    @staticmethod
    def text(
        title: str,
        content: str,
        score: int = 0,
        max_score: int = 0,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:

        return {
            "title": title,
            "type": "text",
            "description": description,
            "content": content,
            "score": score,
            "max_score": max_score,
        }

    @staticmethod
    def chart(
        title: str,
        labels: List[str],
        values: List[Any],
        chart_type: str = "bar",
        description: Optional[str] = None,
        score: int = 0,
        max_score: int = 0,
    ) -> Dict[str, Any]:

        return {
            "title": title,
            "type": "chart",
            "description": description,
            "labels": labels,
            "values": values,
            "chart_type": chart_type,
            "score": score,
            "max_score": max_score,
        }