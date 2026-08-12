import calendar
import re
from datetime import datetime, timezone, timedelta

import feedparser
import httpx
from bs4 import BeautifulSoup

from .fixtures import fixture_items


SOURCE_FEEDS = {
    "The Hacker News": (
        "https://thehackernews.com/feeds/posts/default?alt=rss&max-results=200",
        "https://feeds.feedburner.com/TheHackersNews",
    ),
    "BleepingComputer": ("https://www.bleepingcomputer.com/feed/",),
    "SecurityWeek": ("https://www.securityweek.com/feed/", "https://www.securityweek.com/feed/atom/"),
    "CISA": ("https://www.cisa.gov/cybersecurity-advisories/all.xml", "https://www.cisa.gov/news.xml"),
    "Microsoft MSRC": ("https://msrc.microsoft.com/feed", "https://msrc.microsoft.com/blog/feed"),
    "Ubuntu Security Notices": ("https://ubuntu.com/security/notices/rss.xml", "https://ubuntu.com/security/notices/atom.xml"),
    "Red Hat Security Advisories": ("https://access.redhat.com/security/data/meta/v1/rhsa.rss",),
    "Fortinet PSIRT": ("https://filestore.fortinet.com/fortiguard/rss/ir.xml", "https://fortiguard.fortinet.com/rss/ir.xml"),
    "Cisco Security Advisories": ("https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",),
    "Palo Alto Unit 42": ("https://unit42.paloaltonetworks.com/feed/",),
}


def parse_feed(content: bytes, source: str, limit: int) -> list[dict]:
    parsed=feedparser.parse(content)
    if parsed.bozo and not parsed.entries: raise ValueError(f"Malformed {source} feed")
    items=[]
    for entry in parsed.entries[:limit]:
        published=entry.get("published_parsed") or entry.get("updated_parsed")
        publication_date=datetime.fromtimestamp(calendar.timegm(published),timezone.utc) if published else datetime.now(timezone.utc)
        raw_summary=entry.get("summary") or entry.get("description") or ""
        summary=BeautifulSoup(raw_summary,"html.parser").get_text(" ",strip=True)
        combined=f'{entry.get("title","")} {summary}'
        score_match=re.search(r"\b(?:CVSS(?:\s*v?\d(?:\.\d)?)?(?:\s*(?:base\s*)?score)?|base score)\s*[:=-]?\s*(10(?:\.0)?|[0-9](?:\.\d)?)\b",combined,re.I)
        cvss=float(score_match.group(1)) if score_match else None
        tags=[tag.get("term","") for tag in entry.get("tags",[])]; vendor_severity=next((tag for tag in tags if tag.lower() in {"critical","important","high","moderate","medium","low"}),None)
        if not vendor_severity:
            rating_match=re.search(r"(?:security impact of|RHSA-\d+:\d+:)\s*(Critical|Important|High|Moderate|Medium|Low)\b",combined,re.I)
            if rating_match: vendor_severity=rating_match.group(1)
        link=entry.get("link","")
        if not link.startswith(("https://","http://")): continue
        items.append({"source":source,"title":entry.get("title","Untitled finding"),"summary":summary,"url":link,"publication_date":publication_date,"cvss":cvss,"vendor_severity":vendor_severity})
    return items


def parse_nvd(payload: dict, limit: int) -> list[dict]:
    items=[]
    for wrapper in payload.get("vulnerabilities",[])[:limit]:
        cve=wrapper.get("cve",{}); cve_id=cve.get("id")
        descriptions=cve.get("descriptions",[]); description=next((x.get("value","") for x in descriptions if x.get("lang")=="en"),"")
        if not cve_id or not description: continue
        metrics=cve.get("metrics",{}); cvss=None
        for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if metrics.get(key): cvss=metrics[key][0].get("cvssData",{}).get("baseScore"); break
        published=cve.get("published") or cve.get("lastModified")
        try: publication_date=datetime.fromisoformat(published.replace("Z","+00:00"))
        except (AttributeError,ValueError): publication_date=datetime.now(timezone.utc)
        title=description.split(". ",1)[0].strip()
        items.append({"source":"NVD","title":f"{cve_id}: {title}","summary":description,"url":f"https://nvd.nist.gov/vuln/detail/{cve_id}","publication_date":publication_date,"cvss":cvss})
    return items


async def _collect_nvd(client, limit, days):
    start=(datetime.now(timezone.utc)-timedelta(days=min(max(days,1),120))).isoformat(timespec="milliseconds").replace("+00:00","Z")
    end=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")
    response=await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0",params={"pubStartDate":start,"pubEndDate":end,"resultsPerPage":min(limit,2000)})
    response.raise_for_status(); return parse_nvd(response.json(),limit)


async def collect_source(source: str, timeout: int, limit: int, live: bool=True, days: int=7) -> tuple[list[dict],str]:
    if not live: return fixture_items(source),"fixture"
    headers={"User-Agent":"MyThreatLens/1.0 (+local threat monitoring)","Accept":"application/rss+xml, application/atom+xml, application/xml, text/xml, application/json"}
    errors=[]
    async with httpx.AsyncClient(timeout=timeout,follow_redirects=True,max_redirects=3,headers=headers) as client:
        if source=="NVD":
            try:
                items=await _collect_nvd(client,limit,days)
                if items: return items,"live API"
            except Exception as exc: errors.append(str(exc))
        for url in SOURCE_FEEDS.get(source,()):
            try:
                response=await client.get(url); response.raise_for_status()
                if len(response.content)>5_000_000: raise ValueError("Feed exceeded response-size limit")
                items=parse_feed(response.content,source,limit)
                if items: return items,"live feed"
            except Exception as exc: errors.append(str(exc))
    fallback=fixture_items(source)
    reason="; ".join(errors[-2:]) or "No public collector is configured for this source"
    return fallback,(f"fixture fallback: {reason}" if fallback else f"unavailable: {reason}")
