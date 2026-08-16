import re
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
def extract_cves(text):
    return sorted({m.group(0).upper() for m in CVE_PATTERN.finditer(text or "")})
def severity(source=None, cvss=None, vendor=None, kev=False, text=""):
    if source: return source.title(), f"Source rating: {source.title()}"
    if cvss is not None:
        level="Critical" if cvss>=9 else "High" if cvss>=7 else "Medium" if cvss>=4 else "Low" if cvss>0 else "Informational"
        return level, f"Calculated from CVSS {cvss:g}"
    if vendor:
        mapping={"important":"High","high":"High","moderate":"Medium","medium":"Medium","critical":"Critical","low":"Low"}
        if vendor.lower() in mapping: return mapping[vendor.lower()], f"Vendor rating: {vendor.title()}"
    if kev: return "High", "High operational priority: CISA KEV active exploitation"
    explicit_patterns=(
        r"\b(critical|high|medium|moderate|low)[- ](?:severity|risk|priority)\b",
        r"\bseverity\s*(?:rating|score)?\s*[:=-]?\s*(critical|high|medium|moderate|low)\b",
        r"\brated\s+(?:as\s+)?(critical|high|medium|moderate|low)\b",
        r"\bsecurity impact of\s+(critical|important|high|medium|moderate|low)\b",
        r"\b(critical|high|medium|moderate|low)\s+(?:vulnerabilit(?:y|ies)|flaw|bug)\b",
    )
    for pattern in explicit_patterns:
        m=re.search(pattern,text,re.I)
        if m:
            value=m.group(1).lower(); level="High" if value=="important" else "Medium" if value=="moderate" else value.title()
            return level, "Derived from explicit severity wording in the source"
    if re.search(r"\b(?:actively exploited|active exploitation|exploited in the wild|zero[- ]day|0-day)\b",text,re.I):
        return "High","High operational priority: source reports active exploitation or a zero-day"
    if re.search(r"\b(?:remote code execution|arbitrary code execution|authentication bypass|privilege escalation)\b",text,re.I):
        return "High","Impact-based estimate: source describes a high-impact vulnerability class"
    if re.search(r"\b(?:cross-site scripting|SQL injection|command injection|directory traversal|server-side request forgery)\b",text,re.I):
        return "Medium","Impact-based estimate from the vulnerability class described by the source"
    return "Informational","No reliable severity rating was published"
def relevance(t, k, cvss=None, kev=False, text=""):
    score=min(100, int(t*.7+k*.7+(20 if kev else 0)+(min(cvss or 0,10)*2)+(8 if re.search(r"\b(?:actively exploited|proof.of.concept|PoC)\b",text,re.I) else 0)))
    return score, "High" if score>=75 else "Medium" if score>=45 else "Low", f"Technology {t}/50; keyword {k}/50" + ("; CISA KEV" if kev else "")
