import json
from pathlib import Path
from .models import Rule, new_id


def load_kisa_catalog(path: str | Path) -> list[Rule]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = []
    for group in data["kisa_security_weaknesses"]:
        for item in group["items"]:
            rules.append(Rule(new_id(), item["rule_code"], item["name"], item["name"], group["category_name"], item["num"], None, "MEDIUM"))
    return rules
