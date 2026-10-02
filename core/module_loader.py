import importlib
import pkgutil
from pathlib import Path
from typing import List
from core.base_module import BaseModule

def load_modules(package_path: str = "modules") -> List[BaseModule]:
    """Dynamically loads all classes inheriting from BaseModule inside the modules directory."""
    modules = []
    base_dir = Path(__file__).resolve().parent.parent / package_path

    # Iterate through all files in the modules directory recursively
    for path in base_dir.rglob("*.py"):
        if path.name == "__init__.py":
            continue
            
        # Convert path to python module path (e.g. modules.passive.robots)
        rel_path = path.relative_to(base_dir.parent)
        module_name = str(rel_path.with_suffix('')).replace('\\', '.').replace('/', '.')

        try:
            mod = importlib.import_module(module_name)
            # Find any class in the module that inherits from BaseModule (but is not BaseModule itself)
            for item_name in dir(mod):
                item = getattr(mod, item_name)
                if isinstance(item, type) and issubclass(item, BaseModule) and item is not BaseModule:
                    modules.append(item())
        except Exception as e:
            print(f"[!] Failed to load plugin {module_name}: {e}")

    return modules
