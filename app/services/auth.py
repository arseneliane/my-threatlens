import base64
import hashlib
import secrets

PASSWORD_ITERATIONS=600_000

def normalize_username(username):
    return (username or "").strip().lower()

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
