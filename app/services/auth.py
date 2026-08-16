import base64
import hashlib
import re
import secrets

USERNAME_PATTERN=re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$")
PASSWORD_ITERATIONS=600_000

def normalize_username(username):
    return (username or "").strip().lower()

def validate_username(username):
    username=(username or "").strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must be 3 to 32 characters, start with a letter, and use only letters, numbers, dots, hyphens, or underscores.")
    return username

def validate_password(password,username=""):
    password=password or ""
    errors=[]
    if len(password)<12: errors.append("at least 12 characters")
    if len(password)>128: errors.append("no more than 128 characters")
    if not re.search(r"[A-Z]",password): errors.append("an uppercase letter")
    if not re.search(r"[a-z]",password): errors.append("a lowercase letter")
    if not re.search(r"\d",password): errors.append("a number")
    if not re.search(r"[^A-Za-z0-9]",password): errors.append("a symbol")
    normalized=normalize_username(username)
    if normalized and len(normalized)>=3 and normalized in password.lower(): errors.append("a password that does not contain the username")
    if errors: raise ValueError("Password must include "+", ".join(errors)+".")
    return password

def hash_password(password):
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt,PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"

def verify_password(password,encoded):
    try:
        algorithm,iterations,salt_text,digest_text=encoded.split("$",3)
        if algorithm!="pbkdf2_sha256": return False
        salt=base64.urlsafe_b64decode(salt_text.encode())
        expected=base64.urlsafe_b64decode(digest_text.encode())
        actual=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt,int(iterations))
        return secrets.compare_digest(actual,expected)
    except (TypeError,ValueError):
        return False

def new_session_token(): return secrets.token_urlsafe(32)
def session_token_hash(token): return hashlib.sha256((token or "").encode("utf-8")).hexdigest()
