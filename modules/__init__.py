"""
Author : 0ct0pu3
Version : 1.0.0

Automatic Module Discovery
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

from core.base_module import BaseModule


# ==========================================================
# Category Priority
# ==========================================================

CATEGORY_PRIORITY = {
    "Core": 0,
    "Web": 1,
    "Passive": 2,
    "Security": 3,
    "Custom": 4,
}


# ==========================================================
# Discover Modules
# ==========================================================

def discover_modules():

    discovered = []
    seen = set()

    root = Path(__file__).parent

    for file in root.rglob("*.py"):

        # Ignore package files
        if file.name == "__init__.py":
            continue

        # Ignore hidden files
        if file.name.startswith("_"):
            continue

        # Build import path
        relative = file.relative_to(root)

        module_name = (
            "modules."
            + ".".join(relative.with_suffix("").parts)
        )

        try:

            module = importlib.import_module(module_name)

        except Exception as e:

            print(
                f"[OctoRecon] Failed to import "
                f"{module_name}: {e}"
            )

            continue

        for _, cls in inspect.getmembers(
            module,
            inspect.isclass,
        ):

            if cls is BaseModule:
                continue

            if not issubclass(
                cls,
                BaseModule,
            ):
                continue

            if inspect.isabstract(cls):
                continue

            key = (
                cls.__module__,
                cls.__name__,
            )

            if key in seen:
                continue

            seen.add(key)

            try:

                discovered.append(cls())

            except Exception as e:

                print(
                    f"[OctoRecon] Failed to "
                    f"initialize {cls.__name__}: {e}"
                )

    return discovered
# ==========================================================
# Sort Modules
# ==========================================================

def sort_modules(modules):

    return sorted(
        modules,
        key=lambda module: (
            CATEGORY_PRIORITY.get(
                getattr(
                    module,
                    "category",
                    "Others",
                ),
                999,
            ),
            getattr(
                module,
                "name",
                module.__class__.__name__,
            ).lower(),
        ),
    )


# ==========================================================
# Module Registry
# ==========================================================

MODULES = sort_modules(
    discover_modules()
)


# ==========================================================
# Debug
# ==========================================================

if __name__ == "__main__":

    print()

    print("=" * 60)
    print("Discovered Modules")
    print("=" * 60)

    for module in MODULES:

        print(
            f"{module.category:<10} "
            f"{module.name}"
        )

    print("=" * 60)
    print(f"Total : {len(MODULES)}")