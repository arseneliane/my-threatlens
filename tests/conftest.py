import os, tempfile
_db_path=os.path.join(tempfile.gettempdir(),"my_threatlens_test.db")
try: os.remove(_db_path)
except FileNotFoundError: pass
os.environ["DATABASE_URL"]="sqlite:///"+_db_path.replace("\\","/")
os.environ["LIVE_COLLECTORS_ENABLED"]="false"
import pytest
import itertools
from fastapi.testclient import TestClient
from app.main import app

_users=itertools.count(1)

@pytest.fixture
def client():
    with TestClient(app) as c:
        username=f"test_user_{next(_users)}"
        response=c.post("/register",data={"username":username,"password":"Test-only-123","password_confirm":"Test-only-123"},follow_redirects=False)
        assert response.status_code==303
        c.test_username=username
        yield c
