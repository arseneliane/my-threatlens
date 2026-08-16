import re
from .aliases import TECH_ALIASES, KEYWORD_ALIASES

def _matches(text, patterns):
    return [m.group(0) for p in patterns for m in re.finditer(p, text or "", re.I)]

def match_item(text: str, technologies: list[str], keywords: list[str]):
    tech = {name: _matches(text, TECH_ALIASES.get(name, [rf"\b{re.escape(name)}\b"])) for name in technologies}
    keys = {name: _matches(text, KEYWORD_ALIASES.get(name, [rf"\b{re.escape(name)}\b"])) for name in keywords}
    tech = {k:v for k,v in tech.items() if v}; keys = {k:v for k,v in keys.items() if v}
    return {"relevant": bool(tech and keys), "technologies": list(tech), "keywords": list(keys),
            "technology_score": min(50, 35 + len(tech)*5) if tech else 0,
            "keyword_score": min(50, 35 + len(keys)*5) if keys else 0,
            "evidence": [f"{k}: {v[0]}" for k,v in {**tech, **keys}.items()][:8]}
