from __future__ import annotations
import json
import yaml
from pathlib import Path
from typing import List, Dict, Optional
from ..models import DorkTemplate

DEFAULT_TEMPLATES_FILE = Path(__file__).parent / "default_templates.yaml"

class TemplateRegistry:
    """Manages built-in and user-provided dork templates."""

    def __init__(self, custom_path: Optional[Path] = None):
        self._templates: Dict[str, DorkTemplate] = {}
        self.load_defaults()
        if custom_path and custom_path.exists():
            self.load_custom(custom_path)

    def load_defaults(self):
        """Load default core templates from package YAML."""
        if DEFAULT_TEMPLATES_FILE.exists():
            with open(DEFAULT_TEMPLATES_FILE, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                for item in data.get("templates", []):
                    tpl = DorkTemplate(**item)
                    self._templates[tpl.id] = tpl

    def load_custom(self, path: Path) -> int:
        """Import custom templates from JSON or YAML file."""
        count = 0
        with open(path, "r", encoding="utf-8") as f:
            if path.suffix.lower() in [".yaml", ".yml"]:
                data = yaml.safe_load(f) or {}
            else:
                data = json.load(f) or {}

        items = data.get("templates", data) if isinstance(data, dict) else data
        if isinstance(items, list):
            for item in items:
                try:
                    tpl = DorkTemplate(**item)
                    self._templates[tpl.id] = tpl
                    count += 1
                except Exception:
                    pass
        return count

    def get_all(self) -> List[DorkTemplate]:
        return list(self._templates.values())

    def get_by_id(self, template_id: str) -> Optional[DorkTemplate]:
        return self._templates.get(template_id)

    def get_by_category(self, category: str) -> List[DorkTemplate]:
        cat_lower = category.lower().strip()
        return [t for t in self._templates.values() if cat_lower in t.category.lower()]

    def get_categories(self) -> List[str]:
        return sorted(list({t.category for t in self._templates.values()}))

    def add_template(self, template: DorkTemplate):
        self._templates[template.id] = template

    def remove_template(self, template_id: str) -> bool:
        if template_id in self._templates:
            del self._templates[template_id]
            return True
        return False

# Global instance for shared access
template_registry = TemplateRegistry()
