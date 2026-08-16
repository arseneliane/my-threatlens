import re
import smtplib
import ssl
import time
from collections import Counter
from email.message import EmailMessage
from html import escape
import httpx

EMAIL_PATTERN=re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
SEVERITY_COLORS={"Critical":"#b42318","High":"#dc6803","Medium":"#b78b00","Low":"#07835d","Informational":"#667085"}
ZOHO_TOKEN_CACHE={"access_token":"","expires_at":0.0,"account_id":""}

class EmailDeliveryError(Exception): pass

def render_findings_html(findings,setup,intro=""):
    counts=Counter(f.severity for f in findings)
    count_text=" · ".join(f"{escape(level)} {counts[level]}" for level in ("Critical","High","Medium","Low","Informational") if counts[level]) or "No matching findings"
    cards=[]
    for f in findings:
        cves=", ".join(f.cves or []) or "No CVE"; published=f.publication_date.strftime("%Y-%m-%d")
        cards.append(f'''<div style="padding:14px 0;border-bottom:1px solid #e4edf2"><div style="margin-bottom:7px"><span style="display:inline-block;background:{SEVERITY_COLORS.get(f.severity,'#667085')};color:#fff;padding:3px 8px;border-radius:999px;font-size:12px;font-weight:700">{escape(f.severity)}</span> <span style="color:#526b7a;font-size:12px">{escape(f.technology)}</span></div><a style="color:#075985;font-size:15px;font-weight:700;text-decoration:none" href="{escape(f.url,quote=True)}">{escape(f.title)}</a><div style="color:#64748b;font-size:12px;margin-top:6px">{escape(cves)} · {escape(f.source)} · {published}</div></div>''')
    findings_html="".join(cards) if cards else '<div style="padding:24px 0;text-align:center;color:#64748b">No findings matched the current filters.</div>'
    setup_name=getattr(setup,"display_name",setup.name)
    intro_html=f'<p style="margin:0 0 18px;color:#526b7a">{escape(intro.strip())}</p>' if intro.strip() else ""
    threat_label="threat" if len(findings)==1 else "threats"
    return f'''<!doctype html><html><body style="margin:0;background:#f4f8fa;font:14px Arial,sans-serif;color:#183042"><div style="max-width:700px;margin:auto;background:#fff"><div style="padding:22px 24px;background:#075985;color:#fff"><h1 style="font-size:21px;margin:0 0 5px">My ThreatLens</h1><div>Security findings brief · {escape(setup_name)}</div></div><div style="padding:22px 24px">{intro_html}<div style="padding:12px 14px;background:#eef5f8;border-radius:8px"><strong>{len(findings)} selected {threat_label}</strong><div style="color:#526b7a;font-size:12px;margin-top:4px">{count_text}</div></div><div>{findings_html}</div><p style="margin-top:22px;color:#64748b;font-size:11px">Verify each finding against its linked primary source and your organization's asset inventory.</p></div></div></body></html>'''

def zoho_configured(settings):
    return all((settings.zoho_client_id,settings.zoho_client_secret,settings.zoho_refresh_token,settings.zoho_from_email))

def zoho_access_token(settings,client):
    if ZOHO_TOKEN_CACHE["access_token"] and ZOHO_TOKEN_CACHE["expires_at"]>time.monotonic()+60:
        return ZOHO_TOKEN_CACHE["access_token"]
    try:
        response=client.post(f'{settings.zoho_accounts_base_url.rstrip("/")}/oauth/v2/token',data={"refresh_token":settings.zoho_refresh_token,"client_id":settings.zoho_client_id,"client_secret":settings.zoho_client_secret,"grant_type":"refresh_token"})
        payload=response.json()
    except (httpx.HTTPError,ValueError) as exc:
        raise EmailDeliveryError("Zoho authentication could not be reached. Try again shortly.") from exc
    token=payload.get("access_token") if response.is_success else None
    if not token:
        raise EmailDeliveryError("Zoho authorization needs to be renewed by the site owner.")
    ZOHO_TOKEN_CACHE.update(access_token=token,expires_at=time.monotonic()+int(payload.get("expires_in",3600)),account_id="")
    return token

def zoho_account_id(settings,client,token):
    if ZOHO_TOKEN_CACHE["account_id"]: return ZOHO_TOKEN_CACHE["account_id"]
    try:
        response=client.get(f'{settings.zoho_mail_base_url.rstrip("/")}/api/accounts',headers={"Authorization":f"Zoho-oauthtoken {token}","Accept":"application/json"})
        payload=response.json()
    except (httpx.HTTPError,ValueError) as exc:
        raise EmailDeliveryError("Zoho Mail account information could not be retrieved.") from exc
    target=settings.zoho_from_email.strip().lower()
    account=next((row for row in payload.get("data",[]) if target in {str(row.get("primaryEmailAddress","")).lower(),str(row.get("mailboxAddress","")).lower(),str(row.get("incomingUserName","")).lower()}),None)
    if not response.is_success or not account or not account.get("accountId"):
        raise EmailDeliveryError("The configured Zoho sender address is not available to this authorization.")
    ZOHO_TOKEN_CACHE["account_id"]=str(account["accountId"])
    return ZOHO_TOKEN_CACHE["account_id"]

def send_via_zoho(settings,recipient,subject,html):
    with httpx.Client(timeout=20.0) as client:
        token=zoho_access_token(settings,client)
        account_id=zoho_account_id(settings,client,token)
        try:
            response=client.post(f'{settings.zoho_mail_base_url.rstrip("/")}/api/accounts/{account_id}/messages',headers={"Authorization":f"Zoho-oauthtoken {token}","Accept":"application/json","Content-Type":"application/json"},json={"fromAddress":settings.zoho_from_email,"toAddress":recipient,"subject":subject,"content":html,"mailFormat":"html","encoding":"UTF-8","askReceipt":"no"})
            payload=response.json()
        except (httpx.HTTPError,ValueError) as exc:
            raise EmailDeliveryError("Zoho Mail could not send the message. Try again shortly.") from exc
    if not response.is_success or int(payload.get("status",{}).get("code",0)) not in range(200,300):
        raise EmailDeliveryError("Zoho Mail rejected the message. The site owner should review the Zoho authorization.")

def send_findings_email(settings,recipient,subject,body,findings,setup):
    recipient=recipient.strip(); subject=subject.strip()
    if not EMAIL_PATTERN.fullmatch(recipient): raise ValueError("Enter a valid recipient email address.")
    if not subject or "\r" in subject or "\n" in subject: raise ValueError("Enter a valid email subject.")
    html=render_findings_html(findings,setup,body)
    if zoho_configured(settings):
        send_via_zoho(settings,recipient,subject,html); return
    if not settings.smtp_host or not settings.smtp_from_email:
        location="the Render environment settings" if settings.secure_cookies else "the .env file"
        raise RuntimeError(f"Email is not configured. The site owner must connect Zoho Mail or add SMTP settings in {location}, then restart My ThreatLens. You can use Export in the meantime.")
    if settings.smtp_username and not settings.smtp_password:
        location="the Render environment settings" if settings.secure_cookies else "the .env file"
        raise RuntimeError(f"Email authentication is incomplete. Add the mail provider's app-specific password as SMTP_PASSWORD in {location}, then restart My ThreatLens.")
    message=EmailMessage(); message["From"]=settings.smtp_from_email; message["To"]=recipient; message["Subject"]=subject
    message.set_content((body.strip()+"\n\n" if body.strip() else "")+f"This My ThreatLens report contains {len(findings)} findings. View it in an HTML-capable email client.")
    message.add_alternative(html,subtype="html")
    smtp_class=smtplib.SMTP_SSL if settings.smtp_use_ssl else smtplib.SMTP; kwargs={"host":settings.smtp_host,"port":settings.smtp_port,"timeout":20}
    if settings.smtp_use_ssl: kwargs["context"]=ssl.create_default_context()
    with smtp_class(**kwargs) as server:
        if settings.smtp_use_tls and not settings.smtp_use_ssl: server.starttls(context=ssl.create_default_context())
        if settings.smtp_username: server.login(settings.smtp_username,settings.smtp_password)
        server.send_message(message)
