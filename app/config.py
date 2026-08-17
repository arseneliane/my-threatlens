from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    app_host: str = "127.0.0.1"
    app_port: int = 8001
    database_url: str = f"sqlite:///{(ROOT / 'data' / 'my_threatlens.db').as_posix()}"
    scan_interval_seconds: int = 1800
    request_timeout_seconds: int = 12
    max_results_per_source: int = 200
    results_page_size: int = 50
    max_upload_bytes: int = 5 * 1024 * 1024
    live_collectors_enabled: bool = True
    secure_cookies: bool = False
    public_base_url: str = "http://127.0.0.1:8001"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    zoho_client_id: str = ""
    zoho_client_secret: str = ""
    zoho_refresh_token: str = ""
    zoho_from_email: str = ""
    zoho_accounts_base_url: str = "https://accounts.zoho.com"
    zoho_mail_base_url: str = "https://mail.zoho.com"
    automatic_email_recipient: str = ""
    automatic_email_timezone: str = "Asia/Beirut"
    automatic_email_hour: int = 9
    automatic_email_minute: int = 0
    automatic_email_setup_name: str = ""
    critical_email_enabled: bool = True
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "gpt-oss:20b"
    ollama_api_key: str = ""
    ollama_timeout_seconds: int = 120
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

settings = Settings()
