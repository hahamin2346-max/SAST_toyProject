import json
from pathlib import Path
from .models import Rule, new_id
from .rules import RULE_SPECS


def load_kisa_catalog(path: str | Path) -> list[Rule]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = []
    for group in data["kisa_security_weaknesses"]:
        for item in group["items"]:
            spec = RULE_SPECS.get(item["rule_code"])
            rules.append(Rule(
                new_id(), item["rule_code"], item["name"],
                spec.description if spec else item["name"],
                group["category_name"], item["num"],
                spec.reference if spec else None,
                spec.severity if spec else "MEDIUM",
            ))
    return rules
