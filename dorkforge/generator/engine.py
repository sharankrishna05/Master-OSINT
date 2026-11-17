from __future__ import annotations
import itertools
import random
import re
from typing import List, Dict, Any, Optional
from ..models import DorkQuery, DorkTemplate
from ..audit import validate_query_safety
from .templates import template_registry

class DorkGenerator:
    """Engine for generating and combinatorially expanding dork queries."""

    def __init__(self, registry=template_registry):
        self.registry = registry

    def generate(
        self,
        domain: str,
        keywords: Optional[List[str]] = None,
        filetypes: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
        inurl: Optional[List[str]] = None,
        intext: Optional[List[str]] = None,
        intitle: Optional[List[str]] = None,
        custom_operators: Optional[List[str]] = None,
        category: Optional[str] = None,
        template_ids: Optional[List[str]] = None,
        dedupe: bool = True,
        shuffle: bool = False,
        limit: Optional[int] = None
    ) -> List[DorkQuery]:
        """
        Generate search dorks across selected templates and combinatorial inputs.
        """
        clean_domain = domain.strip().lower()
        # Remove protocol if present
        clean_domain = re.sub(r"^https?://", "", clean_domain).split("/")[0]

        # 1. Select templates
        templates = self.registry.get_all()
        if category:
            templates = self.registry.get_by_category(category)
        if template_ids:
            templates = [t for t in templates if t.id in template_ids]

        queries: List[DorkQuery] = []

        # 2. Expand each template
        for tpl in templates:
            # Check variable dependencies
            pattern = tpl.pattern
            var_keys = re.findall(r"\{([a-zA-Z0-9_]+)\}", pattern)

            # Build candidate parameter dicts for Cartesian product
            var_options: Dict[str, List[str]] = {}
            for v in var_keys:
                if v == "domain":
                    var_options["domain"] = [clean_domain]
                elif v in ["ext", "filetype", "filetypes"]:
                    var_options[v] = filetypes if filetypes else ["sql", "env", "log", "bak", "conf", "ini", "yml", "json", "xml"]
                elif v in ["kw", "keyword", "keywords"]:
                    var_options[v] = keywords if keywords else ["admin", "login", "secret", "backup", "api"]
                elif v in ["inurl"]:
                    var_options[v] = inurl if inurl else ["admin", "login", "config", "debug"]
                elif v in ["intext"]:
                    var_options[v] = intext if intext else ["password", "database", "token"]
                elif v in ["intitle"]:
                    var_options[v] = intitle if intitle else ["index of", "login", "dashboard"]
                elif v in tpl.default_vars:
                    var_options[v] = tpl.default_vars[v]
                else:
                    var_options[v] = [""]

            # Compute Cartesian product of variables
            keys = list(var_options.keys())
            value_lists = [var_options[k] for k in keys]
            combinations = list(itertools.product(*value_lists))

            for combo in combinations:
                param_dict = dict(zip(keys, combo))
                rendered = pattern
                for k, val in param_dict.items():
                    rendered = rendered.replace(f"{{{k}}}", str(val))

                # Clean up excess spaces or empty operators
                rendered = re.sub(r"\s+", " ", rendered).strip()

                if validate_query_safety(rendered):
                    queries.append(DorkQuery(
                        query=rendered,
                        category=tpl.category,
                        template_id=tpl.id,
                        description=tpl.description,
                        parameters=param_dict
                    ))

        # 3. Incorporate custom operator strings if supplied
        if custom_operators:
            for op in custom_operators:
                full_q = f"site:{clean_domain} {op}".strip()
                if validate_query_safety(full_q):
                    queries.append(DorkQuery(
                        query=full_q,
                        category="Custom Operator",
                        template_id="custom_operator",
                        description="User-defined operator search expression",
                        parameters={"operator": op, "domain": clean_domain}
                    ))

        # 4. Optional Combinatorial Keyword / Filetype synthesis
        if keywords and filetypes:
            for kw, ext in itertools.product(keywords, filetypes):
                combo_q = f"site:{clean_domain} ext:{ext} intext:\"{kw}\""
                if validate_query_safety(combo_q):
                    queries.append(DorkQuery(
                        query=combo_q,
                        category="Combinatorial Sensitive File",
                        template_id="combinatorial_kw_ext",
                        description=f"Generated pair for keyword '{kw}' and extension '{ext}'",
                        parameters={"domain": clean_domain, "keyword": kw, "ext": ext}
                    ))

        # 5. Deduplicate
        if dedupe:
            seen = set()
            unique_queries = []
            for q in queries:
                if q.query not in seen:
                    seen.add(q.query)
                    unique_queries.append(q)
            queries = unique_queries

        # 6. Shuffle
        if shuffle:
            random.shuffle(queries)

        # 7. Limit
        if limit and limit > 0:
            queries = queries[:limit]

        return queries
