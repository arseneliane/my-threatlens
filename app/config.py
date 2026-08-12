from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    app_host: str = "127.0.0.1"
    app_port: int = 8001
    database_url: str = f"sqlite:///{(ROOT / 'data' / 'my_threatlens.db').as_posix()}"
    scan_interval_seconds: int = 300
    request_timeout_seconds: int = 12
    max_results_per_source: int = 200
    results_page_size: int = 50
    max_upload_bytes: int = 5 * 1024 * 1024
    live_collectors_enabled: bool = True
    require_demo_auth: bool = False
    demo_username: str = ""
    demo_password: str = ""
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
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:4b"
    ollama_timeout_seconds: int = 120
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

settings = Settings()
