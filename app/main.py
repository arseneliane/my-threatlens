import asyncio, hashlib, itertools, math, re, secrets, smtplib, uuid
from datetime import date, datetime, timezone, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import delete as sql_delete, select, func, update, and_, inspect
from sqlalchemy.orm import Session
from .config import settings
from .database import Base, engine, get_db, SessionLocal
from .models import Setup, Scan, Finding, ChatMessage, SourceStatus, EmailAutomation, User, UserSession
from .services.collectors.fixtures import fixture_items
from .services.collectors.rss import collect_source
from .services.matching.engine import match_item
from .services.matching.aliases import TECH_ALIASES, KEYWORD_ALIASES
from .services.enrichment.core import extract_cves, severity, relevance
from .services.imports.service import preview, sample_xlsx, sample_docx
from .services.exports.excel import create_workbook
from .services.chat import answer, ai_finding_answer, ai_site_answer, selected_ai_model, selected_ai_provider
from .services.email import send_findings_email, EmailDeliveryError, EMAIL_PATTERN
from .services.auth import hash_password, new_session_token, normalize_username, session_token_hash, verify_password

ROOT=Path(__file__).parent
app=FastAPI(title="My ThreatLens",version="1.0.0")
app.mount("/static",StaticFiles(directory=ROOT/"static"),name="static")
templates=Jinja2Templates(directory=ROOT/"templates")
FINDINGS_CACHE={}
ZERO_DAY_FINDINGS_CACHE={}
SCANS_CACHE={}
CHAT_CACHE={}
SITE_CHAT_CACHE={}
FINDING_IDS=itertools.count(1)
SCAN_IDS=itertools.count(1)
INSTANCE_ID=str(uuid.uuid4())
SESSION_COOKIE="mythreatlens_session"
SESSION_DAYS=30
ZERO_DAY_SCAN_KEYWORDS=["Zero-Day","Active Exploitation","CISA KEV","Proof of Concept"]
AUTOMATIC_EMAIL_STATUS={"enabled":False,"last_daily_sent_at":None,"last_critical_sent_at":None,"last_error":None}
AUTOMATICALLY_ALERTED_FINGERPRINTS=set()
AUTOMATION_SCHEDULER=None

@app.middleware("http")
async def require_account(request:Request,call_next):
    """Resolve a hashed database session and require it outside public routes."""
    request.state.user=None; request.state.client_id=None
    token=request.cookies.get(SESSION_COOKIE,"")
    invalid_token=False
    if token:
        with SessionLocal() as db:
            session=db.scalar(select(UserSession).where(UserSession.token_hash==session_token_hash(token)))
            now=datetime.now(timezone.utc)
            expires=session.expires_at if session else None
            if expires and expires.tzinfo is None: expires=expires.replace(tzinfo=timezone.utc)
            if session and expires>now:
                user=db.get(User,session.user_id)
                if user:
                    request.state.user={"id":user.id,"username":user.username}
                    request.state.client_id=f"user:{user.id}"
            elif session:
                db.delete(session); db.commit()
            if request.state.user is None: invalid_token=True
    public=request.url.path in {"/login","/register","/healthz"} or request.url.path.startswith("/static/")
    if not public and request.state.user is None:
        if request.url.path.startswith("/api/"):
            response=JSONResponse(status_code=401,content={"detail":"Log in to continue."})
        else:
            target=request.url.path if request.url.path.startswith("/") and not request.url.path.startswith("//") else "/"
            response=RedirectResponse(f"/login?next={target}",status_code=303)
    else: response=await call_next(request)
    if invalid_token: response.delete_cookie(SESSION_COOKIE,path="/")
    response.headers.setdefault("X-Content-Type-Options","nosniff")
    response.headers.setdefault("X-Frame-Options","DENY")
    response.headers.setdefault("Referrer-Policy","strict-origin-when-cross-origin")
    if request.url.path.startswith("/api/") or response.headers.get("content-type","").startswith("text/html"):
        response.headers.setdefault("Cache-Control","no-store")
    return response

class SetupIn(BaseModel):
    name:str; description:str=""; technologies:list[str]=[]; keywords:list[str]=[]; sources:list[str]=[]; date_range:str="7d"; start_date:date|None=None; end_date:date|None=None
class ChatIn(BaseModel): question:str
class ReviewIn(BaseModel): notes:str=""; review_state:str="Open"; checklist:dict={}
class EmailIn(BaseModel):
    recipient:str
    subject:str="My ThreatLens findings report"
    message:str="Attached is the requested My ThreatLens findings report."
    finding_ids:list[int]=[]
class EmailAutomationIn(BaseModel):
    recipients:list[str]=[]
    daily_enabled:bool=True
    critical_enabled:bool=True
    subject:str="My ThreatLens security alert"
    message:str="Kindly review the threats below and take the required action."
class EmailProviderIn(BaseModel):
    sender_email:str
    app_password:str=""
    smtp_host:str=""
    smtp_port:int|None=None
    security:str="auto"
    clear_password:bool=False

class WorkspaceRestore(BaseModel):
    setups:list[SetupIn]
    active_name:str|None=None

def serial_setup(s):
    result={k:getattr(s,k) for k in ("id","description","technologies","keywords","sources","date_range","start_date","end_date","active","next_scan_at","last_scan_at")}
    result["name"]=s.display_name
    return result

def internal_setup_name(owner_id,display_name): return f"{owner_id}:{uuid.uuid4().hex}:{display_name}"

def ensure_workspace(db,owner_id):
    rows=db.scalars(select(Setup).where(Setup.owner_id==owner_id).order_by(Setup.id)).all()
    if not rows:
        # Preserve pre-upgrade local setups by assigning them to the first account.
        rows=db.scalars(select(Setup).where(Setup.owner_id=="legacy").order_by(Setup.id)).all()
        if rows:
            for setup in rows:
                setup.owner_id=owner_id
                setup.display_name=setup.display_name or setup.name
                setup.name=internal_setup_name(owner_id,setup.display_name)
        else:
            rows=[Setup(name=internal_setup_name(owner_id,"Default Setup"),display_name="Default Setup",owner_id=owner_id,active=True,technologies=["Windows 11","Outlook Web Access","Exchange Server","FortiGate"],keywords=["CVE","Exploit","RCE","Authentication Bypass"],sources=["BleepingComputer","CISA","Microsoft MSRC"],next_scan_at=datetime.now(timezone.utc)+timedelta(seconds=settings.scan_interval_seconds))]
            db.add(rows[0])
        db.commit()
    active=next((setup for setup in rows if setup.active),None)
    if not active:
        rows[0].active=True; db.commit(); active=rows[0]
    return active

def owned_setup(db,owner_id,sid):
    return db.scalar(select(Setup).where(Setup.id==sid,Setup.owner_id==owner_id))
def quick_summary(f):
    source_text=(f.summary or f.title or "A security finding was identified.").strip()
    if source_text and source_text[-1] not in ".!?": source_text+="."
    if len(source_text)>260: source_text=source_text[:257].rsplit(" ",1)[0]+"…"
    cve_text=f" It involves {', '.join(f.cves[:2])}." if f.cves else ""
    priority="Immediate validation and vendor-guided remediation are recommended." if f.severity in ("Critical","High") or f.kev else "Compare the affected versions with your environment and follow the cited vendor guidance."
    return f"This {f.severity.lower()}-priority finding from {f.source} is relevant to {f.technology}. {source_text}{cve_text} Its relevance score is {f.ai_score}/100 with {f.ai_confidence.lower()} confidence. {priority}"

def repair_legacy_fixture_links(db):
    repairs={
        "Russian Hackers Exploit Microsoft OWA Flaw in Active Attacks":{
            "title":"CISA Orders Federal Agencies to Patch Microsoft Exchange Flaw",
            "summary":"CISA ordered agencies to mitigate the high-severity Microsoft Exchange hybrid vulnerability CVE-2025-53786. The flaw can enable privilege escalation from an on-premises Exchange server into the connected cloud environment.",
            "source":"BleepingComputer",
            "url":"https://www.bleepingcomputer.com/news/security/cisa-orders-fed-agencies-to-patch-new-cve-2025-53786-exchange-flaw/",
            "cvss":8.0,"kev":False,"severity":"High","severity_basis":"Calculated from CVSS 8"},
        "CISA Adds FortiOS Vulnerability to Known Exploited Vulnerabilities Catalog":{"url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2024-55591"},
        "Windows Security Update Addresses Critical RCE":{"url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-47981"},
        "Ubuntu security update for PostgreSQL":{"title":"Ubuntu Security Update for PostgreSQL","url":"https://ubuntu.com/security/notices/USN-7315-1","cvss":8.1},
        "Cisco ASA authentication bypass advisory":{"title":"Cisco ASA and FTD VPN Web Server Remote Code Execution Vulnerability","url":"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-z5xP8EUB","cvss":9.9},
        "PAN-OS zero-day exploit observed":{"title":"PAN-OS Authentication Bypass Exploit Attempts Observed","url":"https://security.paloaltonetworks.com/CVE-2025-0108"},
    }
    for finding in db.scalars(select(Finding).where(Finding.title.in_(repairs))).all():
        repair=repairs[finding.title]
        for field,value in repair.items(): setattr(finding,field,value)

def publication_in_setup_range(publication_date, setup, now=None):
    """Return whether a collected item is visible in the setup's date scope."""
    now=now or datetime.now(timezone.utc)
    if publication_date.tzinfo is None:
        publication_date=publication_date.replace(tzinfo=timezone.utc)
    if setup.date_range=="custom":
        if setup.start_date and publication_date<datetime.combine(setup.start_date,datetime.min.time(),tzinfo=timezone.utc): return False
        if setup.end_date and publication_date>=datetime.combine(setup.end_date+timedelta(days=1),datetime.min.time(),tzinfo=timezone.utc): return False
    elif setup.date_range.endswith("d") and setup.date_range[:-1].isdigit():
        if publication_date<now-timedelta(days=int(setup.date_range[:-1])): return False
    return True

def utc_publication_date(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def scoped_findings(db,setup,params):
    """Filter the current in-memory scan. Findings are never persisted to SQLite."""
    if not setup.technologies or not setup.sources: return []
    technologies=set(setup.technologies); keywords=set(setup.keywords)
    requested_keyword=params.get("keyword"); requested_cve=(params.get("cve") or "").upper()
    rows=sorted(FINDINGS_CACHE.get(setup.id,[]),key=lambda f:utc_publication_date(f.publication_date),reverse=True)
    all_technologies_selected=set(TECH_ALIASES).issubset(technologies)
    all_keywords_selected=set(KEYWORD_ALIASES).issubset(keywords)
    matching=[f for f in rows
            if (all_technologies_selected or technologies.intersection(f.matched_technologies or []))
            and (all_keywords_selected or keywords.intersection(f.matched_keywords or []))
            and f.source in setup.sources and publication_in_setup_range(f.publication_date,setup)
            and (not params.get("severity") or f.severity==params["severity"])
            and (not params.get("technology") or f.technology==params["technology"])
            and (not params.get("source") or f.source==params["source"])
            and (not params.get("review_state") or f.review_state==params["review_state"])
            and (not params.get("ai_min") or f.ai_score>=int(params["ai_min"]))
            and (not requested_keyword or requested_keyword in (f.matched_keywords or []))
            and (not requested_cve or requested_cve in (f.cves or []))]
    # Interleave sources so a high-volume vendor feed cannot consume the entire first page.
    groups={}
    for finding in matching: groups.setdefault(finding.source,[]).append(finding)
    source_order=sorted(groups,key=lambda source:utc_publication_date(groups[source][0].publication_date),reverse=True); diversified=[]
    while source_order:
        next_round=[]
        for source in source_order:
            diversified.append(groups[source].pop(0))
            if groups[source]: next_round.append(source)
        source_order=next_round
    return diversified

def scoped_zero_day_findings(setup):
    """Return the focused zero-day scan without mixing it into standard findings."""
    if not setup.technologies or not setup.sources: return []
    technologies=set(setup.technologies)
    rows=sorted(ZERO_DAY_FINDINGS_CACHE.get(setup.id,[]),key=lambda f:utc_publication_date(f.publication_date),reverse=True)
    return [f for f in rows if technologies.intersection(f.matched_technologies or [f.technology]) and f.source in setup.sources and publication_in_setup_range(f.publication_date,setup)]

def cached_finding(fid,db=None,owner_id=None):
    finding=next((finding for cache in (FINDINGS_CACHE,ZERO_DAY_FINDINGS_CACHE) for rows in cache.values() for finding in rows if finding.id==fid),None)
    if finding and db and owner_id and not owned_setup(db,owner_id,finding.setup_id): return None
    return finding

def serial_finding(f):
    return {"id":f.id,"severity":f.severity,"severity_basis":f.severity_basis,"technology":f.technology,"matched_technologies":f.matched_technologies,"matched_keywords":f.matched_keywords,"title":f.title,"summary":f.summary,"ai_summary":quick_summary(f),"url":f.url,"publication_date":f.publication_date,"cves":f.cves,"source":f.source,"ai_score":f.ai_score,"ai_confidence":f.ai_confidence,"ai_reason":f.ai_reason,"review_state":f.review_state,"notes":f.notes,"checklist":f.checklist,"priority_category":priority_category(f)}

def priority_category(f):
    text=f"{f.title or ''} {f.summary or ''}"
    return "zero_day" if re.search(r"\b(?:zero[- ]day|0-day)\b",text,re.I) else "active_exploitation"

def biggest_threat(rows):
    severity_rank={"Critical":4,"High":3,"Medium":2,"Low":1,"Informational":0}
    return max(rows,key=lambda f:(severity_rank.get(f.severity,0),bool(f.kev),f.ai_score or 0,f.cvss or 0,utc_publication_date(f.publication_date)),default=None)

def top_findings(rows,limit):
    severity_rank={"Critical":4,"High":3,"Medium":2,"Low":1,"Informational":0}
    return sorted(rows,key=lambda f:(severity_rank.get(f.severity,0),bool(f.kev),f.ai_score or 0,f.cvss or 0,utc_publication_date(f.publication_date)),reverse=True)[:limit]

def automatic_email_setup(db):
    query=select(Setup).where(Setup.active==True)
    if settings.automatic_email_setup_name.strip(): query=query.where(Setup.display_name==settings.automatic_email_setup_name.strip())
    return db.scalar(query.order_by(Setup.updated_at.desc(),Setup.id.desc()))

def environment_recipients():
    return [value.strip() for value in re.split(r"[,;]",settings.automatic_email_recipient) if value.strip()]

async def deliver_automatic_email(subject,body,rows,setup,status_key,recipients):
    if not recipients or not rows: return False
    sent=False
    for recipient in recipients:
        try:
            await asyncio.to_thread(send_findings_email,settings,recipient,subject,body,rows,setup)
            sent=True
        except Exception as exc:
            AUTOMATIC_EMAIL_STATUS["last_error"]=f"{type(exc).__name__}: automatic email delivery failed"
    if sent:
        AUTOMATIC_EMAIL_STATUS[status_key]=datetime.now(timezone.utc).isoformat()
        AUTOMATIC_EMAIL_STATUS["last_error"]=None
    return sent

async def send_new_critical_alerts(rows,setup):
    setup_key=getattr(setup,"id",getattr(setup,"name","unknown"))
    with SessionLocal() as db:
        config=db.scalar(select(EmailAutomation).where(EmailAutomation.setup_id==getattr(setup,"id",-1)))
        recipients=list(config.recipients or []) if config else environment_recipients()
        enabled=config.critical_enabled if config else settings.critical_email_enabled
        subject=(config.subject if config else "Critical threat detected").strip()
        body=(config.message if config else "Immediate review required.").strip()
    critical=[finding for finding in rows if finding.severity=="Critical"]
    result={"enabled":enabled,"recipient_count":len(recipients),"critical_total":len(critical),"new_critical_count":0,"email_sent":False}
    if not enabled or not recipients: return result
    fresh=[finding for finding in critical if (setup_key,finding.fingerprint) not in AUTOMATICALLY_ALERTED_FINGERPRINTS]
    result["new_critical_count"]=len(fresh)
    if not fresh: return result
    selected=top_findings(fresh,3)
    if await deliver_automatic_email(subject,body,selected,setup,"last_critical_sent_at",recipients):
        AUTOMATICALLY_ALERTED_FINGERPRINTS.update((setup_key,finding.fingerprint) for finding in fresh)
        result["email_sent"]=True
    return result

async def run_daily_email_report():
    with SessionLocal() as db:
        configs=db.scalars(select(EmailAutomation).where(EmailAutomation.daily_enabled==True)).all()
        jobs=[(config.setup_id,list(config.recipients or []),config.subject,config.message) for config in configs if config.recipients]
        if not jobs and environment_recipients():
            setup=automatic_email_setup(db)
            if setup: jobs=[(setup.id,environment_recipients(),"My ThreatLens daily brief","Top findings requiring attention.")]
    for setup_id,recipients,subject,body in jobs:
        with SessionLocal() as db:
            setup=db.get(Setup,setup_id)
            if not setup or not setup.technologies or not setup.keywords or not setup.sources: continue
            scan_id=next(SCAN_IDS); SCANS_CACHE[scan_id]={"id":scan_id,"setup_id":setup.id,"kind":"standard","status":"queued","progress":0,"message":"Scheduled daily scan queued","findings_count":0,"sources":[],"metrics":{},"suppress_critical_email":True}
        await run_scan(scan_id)
        with SessionLocal() as db:
            setup=db.get(Setup,setup_id); rows=[finding for finding in scoped_findings(db,setup,{}) if finding.severity=="Critical"]
            await deliver_automatic_email(subject,body,top_findings(rows,5),setup,"last_daily_sent_at",recipients)

async def run_automatic_critical_scans():
    """Refresh configured setups every interval; run_scan emails new Critical items."""
    with SessionLocal() as db:
        configs=db.scalars(select(EmailAutomation).where(EmailAutomation.critical_enabled==True)).all()
        setup_ids=[config.setup_id for config in configs if config.recipients]
        if not setup_ids and environment_recipients():
            setup=automatic_email_setup(db)
            if setup: setup_ids=[setup.id]
    for setup_id in dict.fromkeys(setup_ids):
        if any(scan.get("setup_id")==setup_id and scan.get("status") in ("queued","running") for scan in SCANS_CACHE.values()): continue
        with SessionLocal() as db:
            setup=db.get(Setup,setup_id)
            if not setup or not setup.technologies or not setup.keywords or not setup.sources: continue
            scan_id=next(SCAN_IDS); SCANS_CACHE[scan_id]={"id":scan_id,"setup_id":setup.id,"kind":"standard","status":"queued","progress":0,"message":"Automatic 30-minute scan queued","findings_count":0,"sources":[],"metrics":{}}
        await run_scan(scan_id)

@app.on_event("startup")
async def startup():
    if settings.database_url.startswith("sqlite"):
        with engine.begin() as conn:
            if "setups" in inspect(conn).get_table_names():
                columns={column["name"] for column in inspect(conn).get_columns("setups")}
                if "display_name" not in columns: conn.exec_driver_sql("ALTER TABLE setups ADD COLUMN display_name VARCHAR(120)")
                if "owner_id" not in columns: conn.exec_driver_sql("ALTER TABLE setups ADD COLUMN owner_id VARCHAR(64)")
                conn.exec_driver_sql("UPDATE setups SET display_name=name WHERE display_name IS NULL OR display_name='' ")
                conn.exec_driver_sql("UPDATE setups SET owner_id='legacy' WHERE owner_id IS NULL OR owner_id='' ")
    Base.metadata.create_all(engine)
    if settings.database_url.startswith("sqlite"):
        with engine.begin() as conn:
            columns={column["name"] for column in inspect(conn).get_columns("email_automations")}
            if "subject" not in columns: conn.exec_driver_sql("ALTER TABLE email_automations ADD COLUMN subject VARCHAR(200) DEFAULT 'My ThreatLens security alert'")
            if "message" not in columns: conn.exec_driver_sql("ALTER TABLE email_automations ADD COLUMN message TEXT DEFAULT 'Kindly review the threats below and take the required action.'")
    with SessionLocal() as db:
        # Remove legacy persisted operational data. Only saved setup configuration remains durable.
        db.execute(sql_delete(SourceStatus)); db.execute(sql_delete(ChatMessage)); db.execute(sql_delete(Finding)); db.execute(sql_delete(Scan))
        FINDINGS_CACHE.clear(); ZERO_DAY_FINDINGS_CACHE.clear(); SCANS_CACHE.clear(); CHAT_CACHE.clear(); SITE_CHAT_CACHE.clear()
        db.commit()
    global AUTOMATION_SCHEDULER
    AUTOMATIC_EMAIL_STATUS["enabled"]=True
    zone=ZoneInfo(settings.automatic_email_timezone)
    AUTOMATION_SCHEDULER=AsyncIOScheduler(timezone=zone)
    AUTOMATION_SCHEDULER.add_job(run_daily_email_report,CronTrigger(hour=settings.automatic_email_hour,minute=settings.automatic_email_minute,timezone=zone),id="daily-email",replace_existing=True,coalesce=True,max_instances=1,misfire_grace_time=86400)
    AUTOMATION_SCHEDULER.add_job(run_automatic_critical_scans,IntervalTrigger(seconds=settings.scan_interval_seconds),id="critical-scan",replace_existing=True,coalesce=True,max_instances=1,misfire_grace_time=None)
    AUTOMATION_SCHEDULER.start()

@app.on_event("shutdown")
async def shutdown():
    global AUTOMATION_SCHEDULER
    if AUTOMATION_SCHEDULER and AUTOMATION_SCHEDULER.running: AUTOMATION_SCHEDULER.shutdown(wait=False)
    AUTOMATION_SCHEDULER=None

@app.exception_handler(Exception)
async def errors(request, exc):
    cid=str(uuid.uuid4())
    return JSONResponse(status_code=500,content={"detail":f"The request could not be completed. Correlation ID: {cid}. Please retry."})

def safe_next(value):
    return value if value and value.startswith("/") and not value.startswith("//") else "/"

def auth_template(request,mode,error="",username="",next_path="/",status_code=200):
    return templates.TemplateResponse(request,"auth.html",{"mode":mode,"error":error,"username":username,"next_path":safe_next(next_path)},status_code=status_code)

def create_user_session(db,user):
    token=new_session_token()
    db.add(UserSession(user_id=user.id,token_hash=session_token_hash(token),expires_at=datetime.now(timezone.utc)+timedelta(days=SESSION_DAYS)))
    db.commit()
    return token

def set_session_cookie(response,request,token):
    # No Max-Age/Expires: authentication ends when the browser session closes.
    response.set_cookie(SESSION_COOKIE,token,httponly=True,secure=settings.secure_cookies or request.url.scheme=="https",samesite="strict",path="/")

@app.get("/login",response_class=HTMLResponse,include_in_schema=False)
def login_page(request:Request,next:str="/"):
    if request.state.user: return RedirectResponse(safe_next(next),status_code=303)
    return auth_template(request,"login",next_path=next)

@app.post("/login",response_class=HTMLResponse,include_in_schema=False)
def login(request:Request,username:str=Form(...),password:str=Form(...),next:str=Form("/"),db:Session=Depends(get_db)):
    normalized=normalize_username(username)
    user=db.scalar(select(User).where(User.username_normalized==normalized))
    if not user or not verify_password(password,user.password_hash):
        return auth_template(request,"login","The username or password is incorrect.",username,next,401)
    token=create_user_session(db,user)
    response=RedirectResponse(safe_next(next),status_code=303); set_session_cookie(response,request,token); return response

@app.get("/register",response_class=HTMLResponse,include_in_schema=False)
def register_page(request:Request):
    if request.state.user: return RedirectResponse("/",status_code=303)
    return auth_template(request,"register")

@app.post("/register",response_class=HTMLResponse,include_in_schema=False)
def register(request:Request,username:str=Form(...),password:str=Form(...),password_confirm:str=Form(...),db:Session=Depends(get_db)):
    username=username.strip(); normalized=normalize_username(username)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,31}",username):
        return auth_template(request,"register","Use 3–32 letters, numbers, dots, underscores, or hyphens; begin with a letter or number.",username,status_code=422)
    if len(password)<10 or not re.search(r"[a-z]",password) or not re.search(r"[A-Z]",password) or not re.search(r"\d",password):
        return auth_template(request,"register","Use at least 10 characters with an uppercase letter, lowercase letter, and number.",username,status_code=422)
    if password!=password_confirm:
        return auth_template(request,"register","The passwords do not match.",username,status_code=422)
    if db.scalar(select(User).where(User.username_normalized==normalized)):
        return auth_template(request,"register","That username is already in use.",username,status_code=409)
    user=User(username=username,username_normalized=normalized,password_hash=hash_password(password)); db.add(user); db.flush()
    token=create_user_session(db,user)
    response=RedirectResponse("/",status_code=303); set_session_cookie(response,request,token); return response

@app.post("/logout",include_in_schema=False)
def logout(request:Request,db:Session=Depends(get_db)):
    token=request.cookies.get(SESSION_COOKIE,"")
    if token:
        session=db.scalar(select(UserSession).where(UserSession.token_hash==session_token_hash(token)))
        if session: db.delete(session); db.commit()
    response=RedirectResponse("/login",status_code=303); response.delete_cookie(SESSION_COOKIE,path="/"); return response

@app.get("/",response_class=HTMLResponse)
def home(request:Request,db:Session=Depends(get_db)):
    active=ensure_workspace(db,request.state.client_id)
    return templates.TemplateResponse(request,"index.html",{"active":active,"username":request.state.user["username"],"scan_interval_seconds":settings.scan_interval_seconds})
@app.get("/healthz",include_in_schema=False)
def healthz(): return {"status":"ok"}
@app.get("/about",response_class=HTMLResponse)
def about(request:Request): return templates.TemplateResponse(request,"about.html",{"version":"1.0.0","username":request.state.user["username"]})
@app.get("/api/workspace")
def workspace(request:Request,db:Session=Depends(get_db)):
    active=ensure_workspace(db,request.state.client_id)
    rows=db.scalars(select(Setup).where(Setup.owner_id==request.state.client_id).order_by(Setup.display_name)).all()
    return {"instance_id":INSTANCE_ID,"username":request.state.user["username"],"active":serial_setup(active),"setups":[serial_setup(s) for s in rows]}
@app.post("/api/workspace/restore")
def restore_workspace(data:WorkspaceRestore,request:Request,db:Session=Depends(get_db)):
    owner=request.state.client_id
    incoming=data.setups[:50] or [SetupIn(name="Default Setup",technologies=["Windows 11"],keywords=["CVE"],sources=["CISA"])]
    unique=[]; names=set()
    for item in incoming:
        clean=item.name.strip()[:120] or "Untitled Setup"
        if clean not in names: names.add(clean); unique.append((item,clean))
    for setup in db.scalars(select(Setup).where(Setup.owner_id==owner)).all():
        for cache in (FINDINGS_CACHE,ZERO_DAY_FINDINGS_CACHE):
            for finding in cache.pop(setup.id,[]): CHAT_CACHE.pop(finding.id,None)
        db.delete(setup)
    db.flush()
    restored=[]
    for item,name in unique:
        values=item.model_dump(); values["name"]=internal_setup_name(owner,name)
        setup=Setup(**values,display_name=name,owner_id=owner,active=name==data.active_name,next_scan_at=datetime.now(timezone.utc)+timedelta(seconds=settings.scan_interval_seconds)); db.add(setup); restored.append(setup)
    if restored and not any(s.active for s in restored): restored[0].active=True
    db.commit()
    return {"instance_id":INSTANCE_ID,"active":serial_setup(next(s for s in restored if s.active)),"setups":[serial_setup(s) for s in restored]}
@app.get("/api/setups")
def setups(request:Request,db:Session=Depends(get_db)):
    ensure_workspace(db,request.state.client_id)
    return [serial_setup(s) for s in db.scalars(select(Setup).where(Setup.owner_id==request.state.client_id).order_by(Setup.display_name)).all()]
@app.post("/api/setups",status_code=201)
def create_setup(data:SetupIn,request:Request,db:Session=Depends(get_db)):
    owner=request.state.client_id
    ensure_workspace(db,owner)
    if db.scalar(select(Setup).where(Setup.owner_id==owner,Setup.display_name==data.name)): raise HTTPException(409,"A setup with this name already exists.")
    db.execute(update(Setup).where(Setup.owner_id==owner).values(active=False)); values=data.model_dump(); values["name"]=internal_setup_name(owner,data.name); s=Setup(**values,display_name=data.name,owner_id=owner,active=True,next_scan_at=datetime.now(timezone.utc)+timedelta(seconds=settings.scan_interval_seconds)); db.add(s); db.commit(); return serial_setup(s)
@app.put("/api/setups/{sid}")
def save_setup(sid:int,data:SetupIn,request:Request,db:Session=Depends(get_db)):
    owner=request.state.client_id; s=owned_setup(db,owner,sid)
    if not s: raise HTTPException(404,"Setup not found.")
    other=db.scalar(select(Setup).where(Setup.owner_id==owner,Setup.display_name==data.name,Setup.id!=sid))
    if other: raise HTTPException(409,"A different setup already uses this name.")
    for k,v in data.model_dump().items(): setattr(s,"display_name" if k=="name" else k,v)
    db.commit(); return serial_setup(s)
@app.post("/api/setups/{sid}/activate")
def activate(sid:int,request:Request,db:Session=Depends(get_db)):
    owner=request.state.client_id; s=owned_setup(db,owner,sid)
    if not s: raise HTTPException(404,"Setup not found.")
    db.execute(update(Setup).where(Setup.owner_id==owner).values(active=False)); s.active=True; db.commit(); return serial_setup(s)
@app.post("/api/setups/{sid}/duplicate")
def duplicate(sid:int,request:Request,db:Session=Depends(get_db)):
    owner=request.state.client_id; s=owned_setup(db,owner,sid)
    if not s: raise HTTPException(404,"Setup not found.")
    name=f"{s.display_name} Copy"; n=1
    while db.scalar(select(Setup).where(Setup.owner_id==owner,Setup.display_name==name)): n+=1; name=f"{s.display_name} Copy {n}"
    db.execute(update(Setup).where(Setup.owner_id==owner).values(active=False)); c=Setup(name=internal_setup_name(owner,name),display_name=name,owner_id=owner,description=s.description,technologies=s.technologies,keywords=s.keywords,sources=s.sources,date_range=s.date_range,active=True,next_scan_at=datetime.now(timezone.utc)+timedelta(seconds=settings.scan_interval_seconds)); db.add(c); db.commit(); return serial_setup(c)
@app.delete("/api/setups/{sid}")
def delete(sid:int,request:Request,db:Session=Depends(get_db)):
    owner=request.state.client_id; s=owned_setup(db,owner,sid)
    if not s: raise HTTPException(404,"Setup not found.")
    if db.scalar(select(func.count()).select_from(Setup).where(Setup.owner_id==owner))<=1:
        raise HTTPException(409,"The last setup cannot be deleted. Create another setup first.")
    was_active=s.active
    for cache in (FINDINGS_CACHE,ZERO_DAY_FINDINGS_CACHE):
        for finding in cache.pop(sid,[]): CHAT_CACHE.pop(finding.id,None)
    for scan_id,scan in list(SCANS_CACHE.items()):
        if scan["setup_id"]==sid: SCANS_CACHE.pop(scan_id,None)
    db.delete(s)
    db.commit()
    first=db.scalar(select(Setup).where(Setup.owner_id==owner))
    if was_active: first.active=True
    active=first if was_active or not db.scalar(select(Setup).where(Setup.owner_id==owner,Setup.active==True)) else db.scalar(select(Setup).where(Setup.owner_id==owner,Setup.active==True))
    db.commit()
    return {"deleted":True,"active":serial_setup(active)}

async def run_scan(scan_id):
    scan=SCANS_CACHE.get(scan_id)
    if not scan: return
    zero_day_mode=scan.get("kind")=="zero_day"
    result_cache=ZERO_DAY_FINDINGS_CACHE if zero_day_mode else FINDINGS_CACHE
    with SessionLocal() as db:
        setup=db.get(Setup,scan["setup_id"]); sources=list(setup.sources); scan_days=int(setup.date_range[:-1]) if setup.date_range.endswith("d") and setup.date_range[:-1].isdigit() else 120
        scan.update(status="running",progress=5,message="Collecting zero-day intelligence" if zero_day_mode else "Collecting approved sources")
    async def collect_safely(source):
        try:
            return await collect_source(source,settings.request_timeout_seconds,settings.max_results_per_source,settings.live_collectors_enabled,scan_days)
        except Exception:
            return [],"unavailable: collector failed safely"
    collected=await asyncio.gather(*(collect_safely(source) for source in sources))
    with SessionLocal() as db:
        setup=db.get(Setup,scan["setup_id"]); results=[]; added=0; added_in_range=0; scan_now=datetime.now(timezone.utc); live_sources=0; seen_fingerprints=set(); source_states=[]; zero_day_mentions=0; active_exploitation=0; critical_priority=0
        all_technologies_selected=set(TECH_ALIASES).issubset(setup.technologies)
        all_keywords_selected=set(KEYWORD_ALIASES).issubset(setup.keywords)
        for finding in result_cache.get(setup.id,[]): CHAT_CACHE.pop(finding.id,None)
        for idx,(source,(raw_items,collector_mode)) in enumerate(zip(sources,collected)):
            scan["message"]=f"Processing {source} ({collector_mode})"
            is_live=collector_mode.startswith("live"); live_sources+=int(is_live)
            source_states.append({"source":source,"status":"live" if is_live else ("fallback" if raw_items else "unavailable"),"reason":f"{len(raw_items)} items collected; {collector_mode}"})
            for raw in raw_items:
                text=raw["title"]+" "+raw["summary"]; m=match_item(text,setup.technologies,ZERO_DAY_SCAN_KEYWORDS if zero_day_mode else setup.keywords)
                if not zero_day_mode:
                    m["relevant"]=(bool(m["technologies"]) or all_technologies_selected) and (bool(m["keywords"]) or all_keywords_selected)
                if not m["relevant"]: continue
                cves=extract_cves(text); sev,basis=severity(cvss=raw.get("cvss"),vendor=raw.get("vendor_severity"),kev=raw.get("kev",False),text=text); score,conf,reason=relevance(m["technology_score"],m["keyword_score"],raw.get("cvss"),raw.get("kev",False),text)
                fp=hashlib.sha256(f'{raw["url"]}|{raw["title"]}|{raw["publication_date"].date()}'.encode()).hexdigest()
                if fp in seen_fingerprints: continue
                seen_fingerprints.add(fp)
                finding=Finding(id=next(FINDING_IDS),setup_id=setup.id,scan_id=scan_id,fingerprint=fp,title=raw["title"],summary=raw["summary"],url=raw["url"],source=source,publication_date=raw["publication_date"],technology=m["technologies"][0] if m["technologies"] else "Other / General",matched_technologies=m["technologies"],matched_keywords=m["keywords"],cves=cves,severity=sev,severity_basis=basis,cvss=raw.get("cvss"),epss=None,kev=raw.get("kev",False),ai_score=score,ai_confidence=conf,ai_reason=reason,evidence=m["evidence"],review_state="Open",notes="",checklist={})
                results.append(finding); added+=1
                if publication_in_setup_range(raw["publication_date"],setup,scan_now):
                    added_in_range+=1
                    if zero_day_mode:
                        zero_day_mentions+=int(bool(re.search(r"\b(?:zero[- ]day|0-day)\b",text,re.I)))
                        active_exploitation+=int(bool(raw.get("kev",False) or re.search(r"\b(?:actively exploited|active exploitation|under active (?:attack|exploitation)|exploited in the wild|exploitation (?:has been )?observed|attacks? exploiting)\b",text,re.I)))
                        critical_priority+=int(sev=="Critical")
            scan["progress"]=min(95,10+int((idx+1)/max(len(sources),1)*80))
        if zero_day_mode:
            metrics={"zero_day_mentions":zero_day_mentions,"active_exploitation":active_exploitation,"critical_priority":critical_priority,"sources_checked":len(sources),"live_sources":live_sources}
        else:
            newest=max((utc_publication_date(finding.publication_date) for finding in results),default=None)
            newest_age_days=max(1,math.ceil((scan_now-newest).total_seconds()/86400)) if newest else None
            recommended_range=next((f"{days}d" for days in (3,7,14,30,60,90) if newest_age_days is not None and days>=newest_age_days),None)
            metrics={"matched_total":added,"in_range":added_in_range,"excluded_by_date":added-added_in_range,"recommended_range":recommended_range,"sources_checked":len(sources),"live_sources":live_sources,"unavailable_sources":len(sources)-live_sources}
        result_cache[setup.id]=results; scan.update(status="completed",progress=100,findings_count=added_in_range,sources=source_states,metrics=metrics)
        scan["message"]=f"Completed — {added_in_range} findings in selected date range"
        if not zero_day_mode and added_in_range==0 and added:
            scan["message"]=f"Completed — no findings were published in the selected date range; {added} older matching items were excluded"
        if zero_day_mode: scan["message"]=f"Zero-day watch completed: {added_in_range} priority signals"
        setup.last_scan_at=datetime.now(timezone.utc); db.commit()
    if not scan.get("suppress_critical_email"):
        scan["automation"]=await send_new_critical_alerts([finding for finding in results if publication_in_setup_range(finding.publication_date,setup,scan_now)],setup)
@app.post("/api/scans",status_code=202)
async def start_scan(request:Request,bg:BackgroundTasks,db:Session=Depends(get_db)):
    setup=ensure_workspace(db,request.state.client_id)
    if not setup: raise HTTPException(400,"No active setup.")
    running=next((scan for scan in SCANS_CACHE.values() if scan["setup_id"]==setup.id and scan["status"] in ("queued","running")),None)
    if running: raise HTTPException(409,"A scan is already running for this setup.")
    # Each scan is a fresh search; do not serve findings from the previous scope.
    for finding in FINDINGS_CACHE.pop(setup.id,[]): CHAT_CACHE.pop(finding.id,None)
    start=datetime.now(timezone.utc); setup.next_scan_at=start+timedelta(seconds=settings.scan_interval_seconds); scan_id=next(SCAN_IDS); SCANS_CACHE[scan_id]={"id":scan_id,"setup_id":setup.id,"kind":"standard","status":"queued","progress":0,"message":"Queued","findings_count":0,"sources":[],"metrics":{}}; db.commit(); bg.add_task(run_scan,scan_id)
    return {"scan_id":scan_id,"status":"queued","next_scan_at":setup.next_scan_at}
@app.post("/api/scans/zero-days",status_code=202)
async def start_zero_day_scan(request:Request,bg:BackgroundTasks,db:Session=Depends(get_db)):
    setup=ensure_workspace(db,request.state.client_id)
    if not setup.technologies or not setup.sources: raise HTTPException(400,"Choose at least one technology and one source before scanning for zero-days.")
    running=next((scan for scan in SCANS_CACHE.values() if scan["setup_id"]==setup.id and scan["status"] in ("queued","running")),None)
    if running: raise HTTPException(409,"A scan is already running for this setup.")
    for finding in ZERO_DAY_FINDINGS_CACHE.pop(setup.id,[]): CHAT_CACHE.pop(finding.id,None)
    start=datetime.now(timezone.utc); setup.next_scan_at=start+timedelta(seconds=settings.scan_interval_seconds); scan_id=next(SCAN_IDS); SCANS_CACHE[scan_id]={"id":scan_id,"setup_id":setup.id,"kind":"zero_day","status":"queued","progress":0,"message":"Zero-day watch queued","findings_count":0,"sources":[],"metrics":{"zero_day_mentions":0,"active_exploitation":0,"critical_priority":0,"sources_checked":0,"live_sources":0}}; db.commit(); bg.add_task(run_scan,scan_id)
    return {"scan_id":scan_id,"status":"queued","next_scan_at":setup.next_scan_at}
@app.get("/api/scans/{scan_id}")
def scan_status(scan_id:int,request:Request,db:Session=Depends(get_db)):
    s=SCANS_CACHE.get(scan_id)
    if not s or not owned_setup(db,request.state.client_id,s["setup_id"]): raise HTTPException(404,"Scan not found.")
    return {k:s.get(k) for k in ("id","kind","status","progress","message","findings_count","sources","metrics","automation")}
@app.get("/api/findings")
def findings(request:Request,page:int=1,page_size:int=settings.results_page_size,db:Session=Depends(get_db)):
    setup=ensure_workspace(db,request.state.client_id); params=dict(request.query_params)
    all_rows=scoped_findings(db,setup,params); total=len(all_rows); pages=max(1,math.ceil(total/page_size)); page=max(1,min(page,pages)); rows=all_rows[(page-1)*page_size:page*page_size]
    biggest=biggest_threat(scoped_findings(db,setup,{}))
    return {"items":[serial_finding(f) for f in rows],"biggest":serial_finding(biggest) if biggest else None,"page":page,"pages":pages,"total":total}
@app.get("/api/zero-day-findings")
def zero_day_findings(request:Request,db:Session=Depends(get_db)):
    setup=ensure_workspace(db,request.state.client_id); rows=scoped_zero_day_findings(setup)
    latest=max((scan for scan in SCANS_CACHE.values() if scan.get("setup_id")==setup.id and scan.get("kind")=="zero_day"),key=lambda scan:scan["id"],default=None)
    zero_days=[f for f in rows if priority_category(f)=="zero_day"]
    exploitation=[f for f in rows if priority_category(f)=="active_exploitation"]
    return {"items":[serial_finding(f) for f in rows],"zero_days":[serial_finding(f) for f in zero_days],"active_exploitation":[serial_finding(f) for f in exploitation],"total":len(rows),"zero_day_total":len(zero_days),"active_exploitation_total":len(exploitation),"scanned":setup.id in ZERO_DAY_FINDINGS_CACHE,"metrics":(latest or {}).get("metrics",{}),"sources":(latest or {}).get("sources",[])}
@app.get("/api/automatic-email/status")
def automatic_email_status():
    recipient=settings.automatic_email_recipient.strip()
    masked=(recipient[:2]+"…@"+recipient.split("@",1)[1]) if "@" in recipient else ""
    return {**AUTOMATIC_EMAIL_STATUS,"recipient":masked,"timezone":settings.automatic_email_timezone,"daily_time":f"{settings.automatic_email_hour:02d}:{settings.automatic_email_minute:02d}","scan_interval_minutes":settings.scan_interval_seconds//60,"critical_alerts":settings.critical_email_enabled}

def automation_setup(db,request,setup_id=None):
    setup=owned_setup(db,request.state.client_id,setup_id) if setup_id is not None else ensure_workspace(db,request.state.client_id)
    if not setup: raise HTTPException(404,"Setup not found.")
    return setup

def smtp_defaults(address):
    domain=address.rsplit("@",1)[-1].lower()
    if domain in {"gmail.com","googlemail.com"}: return "smtp.gmail.com",465,"ssl"
    if domain in {"outlook.com","hotmail.com","live.com","office365.com"}: return "smtp.office365.com",587,"tls"
    if domain in {"yahoo.com","ymail.com"} or domain.startswith("yahoo."): return "smtp.mail.yahoo.com",465,"ssl"
    if domain in {"icloud.com","me.com","mac.com"}: return "smtp.mail.me.com",587,"tls"
    if domain=="zohomail.com" or domain.startswith("zoho."): return "smtp.zoho.com",465,"ssl"
    return "",587,"tls"

def write_env_values(values):
    env_path=ROOT.parent/".env"
    text=env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    for name,value in values.items():
        safe=str(value).replace("\\","\\\\").replace('"','\\"').replace("\r","").replace("\n","")
        line=f'{name}="{safe}"'
        pattern=rf"(?m)^{re.escape(name)}=.*$"
        text=re.sub(pattern,lambda _:line,text) if re.search(pattern,text) else text.rstrip()+"\n"+line+"\n"
    env_path.write_text(text,encoding="utf-8")

@app.get("/api/email-provider")
def get_email_provider():
    sender=(settings.smtp_from_email or settings.smtp_username).strip()
    return {"configured":bool(settings.smtp_host and sender and settings.smtp_password),"sender_email":sender,"smtp_host":settings.smtp_host,"smtp_port":settings.smtp_port,"security":"ssl" if settings.smtp_use_ssl else "tls" if settings.smtp_use_tls else "none","has_password":bool(settings.smtp_password)}

@app.put("/api/email-provider")
def save_email_provider(data:EmailProviderIn):
    sender=data.sender_email.strip().lower()
    if not EMAIL_PATTERN.fullmatch(sender): raise HTTPException(422,"Enter a valid sender email address.")
    detected_host,detected_port,detected_security=smtp_defaults(sender)
    host=(data.smtp_host.strip() or detected_host).lower()
    if not host or not re.fullmatch(r"[a-z0-9.-]+",host): raise HTTPException(422,"Enter the SMTP server supplied by your email provider.")
    security=data.security.lower() if data.security.lower() in {"ssl","tls","none"} else detected_security
    port=data.smtp_port or detected_port
    if not 1<=port<=65535: raise HTTPException(422,"Enter a valid SMTP port.")
    password="" if data.clear_password else data.app_password or settings.smtp_password
    if not password: raise HTTPException(422,"Enter the email app password.")
    values={"SMTP_HOST":host,"SMTP_PORT":port,"SMTP_USERNAME":sender,"SMTP_PASSWORD":password,"SMTP_FROM_EMAIL":sender,"SMTP_USE_TLS":str(security=="tls").lower(),"SMTP_USE_SSL":str(security=="ssl").lower()}
    write_env_values(values)
    for name,value in {"smtp_host":host,"smtp_port":port,"smtp_username":sender,"smtp_password":password,"smtp_from_email":sender,"smtp_use_tls":security=="tls","smtp_use_ssl":security=="ssl"}.items(): setattr(settings,name,value)
    return {"configured":True,"sender_email":sender,"smtp_host":host,"smtp_port":port,"security":security,"has_password":True,"message":"Email sender saved locally."}

@app.get("/api/automatic-email")
def get_automatic_email(request:Request,setup_id:int|None=None,db:Session=Depends(get_db)):
    setup=automation_setup(db,request,setup_id)
    config=db.scalar(select(EmailAutomation).where(EmailAutomation.setup_id==setup.id))
    return {"setup_id":setup.id,"setup_name":setup.display_name,"recipients":list(config.recipients or []) if config else [],"daily_enabled":config.daily_enabled if config else True,"critical_enabled":config.critical_enabled if config else True,"subject":config.subject if config else "My ThreatLens security alert","message":config.message if config else "Kindly review the threats below and take the required action.","timezone":settings.automatic_email_timezone,"daily_time":f"{settings.automatic_email_hour:02d}:{settings.automatic_email_minute:02d}","scan_interval_minutes":settings.scan_interval_seconds//60}
@app.put("/api/automatic-email")
def save_automatic_email(data:EmailAutomationIn,request:Request,setup_id:int|None=None,db:Session=Depends(get_db)):
    setup=automation_setup(db,request,setup_id)
    recipients=[]
    for raw in data.recipients:
        recipient=raw.strip().lower()
        if recipient and recipient not in recipients: recipients.append(recipient)
    if len(recipients)>10: raise HTTPException(422,"Enter no more than 10 email addresses.")
    invalid=[recipient for recipient in recipients if not EMAIL_PATTERN.fullmatch(recipient)]
    if invalid: raise HTTPException(422,f"Invalid email address: {invalid[0]}")
    subject=data.subject.strip()
    message=data.message.strip()
    if len(subject)>200: raise HTTPException(422,"The subject must be 200 characters or fewer.")
    if len(message)>1000: raise HTTPException(422,"The message must be 1,000 characters or fewer.")
    if recipients and (not subject or not message): raise HTTPException(422,"Enter both a subject and a message.")
    config=db.scalar(select(EmailAutomation).where(EmailAutomation.setup_id==setup.id))
    if not config:
        config=EmailAutomation(setup_id=setup.id); db.add(config)
    config.recipients=recipients; config.daily_enabled=data.daily_enabled; config.critical_enabled=data.critical_enabled
    config.subject=subject or "My ThreatLens security alert"; config.message=message or "Kindly review the threats below and take the required action."
    db.commit()
    return get_automatic_email(request,setup.id,db)
@app.post("/api/automatic-email/test")
async def test_automatic_email(request:Request,setup_id:int|None=None,db:Session=Depends(get_db)):
    setup=automation_setup(db,request,setup_id)
    config=db.scalar(select(EmailAutomation).where(EmailAutomation.setup_id==setup.id))
    recipients=list(config.recipients or []) if config else []
    if not recipients: raise HTTPException(422,"Save at least one recipient before sending a test.")
    sent=[]; failed=[]
    for recipient in recipients:
        try:
            await asyncio.to_thread(send_findings_email,settings,recipient,"My ThreatLens automatic email test","Automatic email is configured correctly for this setup.",[],setup)
            sent.append(recipient)
        except Exception:
            failed.append(recipient)
    if not sent: raise HTTPException(503,"The test email could not be delivered. Check the email configuration and try again.")
    return {"sent_count":len(sent),"failed_count":len(failed),"message":f"Test email sent to {len(sent)} of {len(recipients)} recipients."}

@app.post("/api/automatic-email/run-now",status_code=202)
async def run_automatic_email_now(request:Request,bg:BackgroundTasks,setup_id:int|None=None,db:Session=Depends(get_db)):
    setup=automation_setup(db,request,setup_id)
    config=db.scalar(select(EmailAutomation).where(EmailAutomation.setup_id==setup.id))
    if not config or not config.recipients: raise HTTPException(422,"Save at least one recipient before running the critical check.")
    if not config.critical_enabled: raise HTTPException(422,"Enable the new Critical threat option before running the check.")
    if not setup.technologies or not setup.keywords or not setup.sources: raise HTTPException(422,"Choose technologies, keywords, and sources for this setup first.")
    running=next((scan for scan in SCANS_CACHE.values() if scan.get("setup_id")==setup.id and scan.get("status") in ("queued","running")),None)
    if running: raise HTTPException(409,"A scan is already running for this setup.")
    scan_id=next(SCAN_IDS)
    SCANS_CACHE[scan_id]={"id":scan_id,"setup_id":setup.id,"kind":"standard","status":"queued","progress":0,"message":"Critical automation check queued","findings_count":0,"sources":[],"metrics":{},"automation":None}
    bg.add_task(run_scan,scan_id)
    return {"scan_id":scan_id,"status":"queued","message":"Critical automation check started."}
@app.put("/api/findings/{fid}/review")
def review(fid:int,data:ReviewIn,request:Request,db:Session=Depends(get_db)):
    f=cached_finding(fid,db,request.state.client_id)
    if not f: raise HTTPException(404,"Finding not found.")
    f.notes=data.notes; f.review_state=data.review_state; f.checklist=data.checklist; return {"saved":True}
@app.post("/api/findings/{fid}/chat")
async def chat(fid:int,data:ChatIn,request:Request,db:Session=Depends(get_db)):
    f=cached_finding(fid,db,request.state.client_id)
    if not f: raise HTTPException(404,"Finding not found.")
    question=data.question.strip()
    if not question: raise HTTPException(422,"Enter a question.")
    if len(question)>2000: raise HTTPException(422,"The question must be 2,000 characters or fewer.")
    history=CHAT_CACHE.setdefault(fid,[])
    pending=ChatMessage(finding_id=fid,role="user",content=question,created_at=datetime.now(timezone.utc))
    try: content=await ai_finding_answer(f,history+[pending],settings)
    except RuntimeError as exc: raise HTTPException(503,str(exc))
    reply=ChatMessage(finding_id=fid,role="assistant",content=content,created_at=datetime.now(timezone.utc)); history.extend([pending,reply])
    return {"message":{"role":"assistant","content":content},"model":selected_ai_model(settings),"provider":selected_ai_provider(settings)}
@app.get("/api/findings/{fid}/chat")
def chat_history(fid:int,request:Request,db:Session=Depends(get_db)):
    if not cached_finding(fid,db,request.state.client_id): raise HTTPException(404,"Finding not found.")
    messages=CHAT_CACHE.get(fid,[])
    return {"messages":[{"role":m.role,"content":m.content,"created_at":m.created_at} for m in messages],"model":selected_ai_model(settings),"provider":selected_ai_provider(settings)}
@app.delete("/api/findings/{fid}/chat")
def clear_chat(fid:int,request:Request,db:Session=Depends(get_db)):
    if not cached_finding(fid,db,request.state.client_id): raise HTTPException(404,"Finding not found.")
    CHAT_CACHE.pop(fid,None); return {"deleted":True}
@app.post("/api/site-chat")
async def site_chat(data:ChatIn,request:Request,db:Session=Depends(get_db)):
    question=data.question.strip()
    if not question: raise HTTPException(422,"Enter a question.")
    if len(question)>2000: raise HTTPException(422,"The question must be 2,000 characters or fewer.")
    setup=ensure_workspace(db,request.state.client_id)
    params={k:v for k,v in request.query_params.items() if k!="page"}
    rows=scoped_findings(db,setup,params)
    cache_key=(request.state.client_id,setup.id)
    history=SITE_CHAT_CACHE.setdefault(cache_key,[])
    pending={"role":"user","content":question,"created_at":datetime.now(timezone.utc).isoformat()}
    try: content=await ai_site_answer(setup,rows,history+[pending],settings)
    except RuntimeError as exc: raise HTTPException(503,str(exc))
    reply={"role":"assistant","content":content,"created_at":datetime.now(timezone.utc).isoformat()}
    history.extend([pending,reply])
    if len(history)>40: del history[:-40]
    return {"message":reply,"model":selected_ai_model(settings),"provider":selected_ai_provider(settings),"context_findings":len(rows)}
@app.get("/api/site-chat")
def site_chat_history(request:Request,db:Session=Depends(get_db)):
    setup=ensure_workspace(db,request.state.client_id)
    return {"messages":SITE_CHAT_CACHE.get((request.state.client_id,setup.id),[]),"model":selected_ai_model(settings),"provider":selected_ai_provider(settings)}
@app.delete("/api/site-chat")
def clear_site_chat(request:Request,db:Session=Depends(get_db)):
    setup=ensure_workspace(db,request.state.client_id)
    SITE_CHAT_CACHE.pop((request.state.client_id,setup.id),None); return {"deleted":True}
@app.get("/api/export")
def export(request:Request,db:Session=Depends(get_db)):
    setup=ensure_workspace(db,request.state.client_id); params=dict(request.query_params); rows=scoped_findings(db,setup,params)
    timestamp=datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    filename=f"My-ThreatLens-Results-{timestamp}.xlsx"
    return Response(create_workbook(rows,setup,params),media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",headers={"Content-Disposition":f'attachment; filename="{filename}"'})
@app.post("/api/email")
def email_findings(data:EmailIn,request:Request,finding_id:int|None=None,db:Session=Depends(get_db)):
    setup=ensure_workspace(db,request.state.client_id); params={k:v for k,v in request.query_params.items() if k!="page"}
    if data.finding_ids:
        finding_ids=list(dict.fromkeys(data.finding_ids))
        if len(finding_ids)>50: raise HTTPException(422,"Select no more than 50 threats per email.")
        rows=[]
        for selected_id in finding_ids:
            finding=cached_finding(selected_id,db,request.state.client_id)
            if not finding or finding.setup_id!=setup.id: raise HTTPException(404,"One or more selected threats were not found.")
            rows.append(finding)
    elif finding_id is not None:
        finding=cached_finding(finding_id,db,request.state.client_id)
        if not finding or finding.setup_id!=setup.id: raise HTTPException(404,"Finding not found.")
        rows=[finding]
    else: rows=scoped_findings(db,setup,params)
    try: send_findings_email(settings,data.recipient,data.subject,data.message,rows,setup)
    except ValueError as exc: raise HTTPException(422,str(exc))
    except EmailDeliveryError as exc: raise HTTPException(502,str(exc))
    except RuntimeError as exc: raise HTTPException(503,str(exc))
    except (OSError,smtplib.SMTPException): raise HTTPException(502,"The mail server could not send the message. Check the SMTP settings and try again.")
    return {"sent":True,"recipient":data.recipient,"findings_count":len(rows)}
@app.post("/api/import/preview")
async def import_preview(file:UploadFile=File(...)):
    ext=Path(file.filename or "").suffix.lower()
    if ext not in (".xlsx",".docx"): raise HTTPException(400,"Only XLSX and DOCX files are supported.")
    data=await file.read(settings.max_upload_bytes+1)
    if len(data)>settings.max_upload_bytes: raise HTTPException(413,"File exceeds the 5 MB upload limit.")
    try: return preview(data,ext)
    except Exception as e: raise HTTPException(400,f"Import validation failed: {e}")
@app.get("/api/import/sample/{kind}")
def sample(kind:str):
    if kind=="xlsx": return Response(sample_xlsx(),media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",headers={"Content-Disposition":'attachment; filename="MyThreatLens-Sample.xlsx"'})
    if kind=="docx": return Response(sample_docx(),media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",headers={"Content-Disposition":'attachment; filename="MyThreatLens-Sample.docx"'})
    raise HTTPException(404)
