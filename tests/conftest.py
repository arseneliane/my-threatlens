import os, tempfile
_db_path=os.path.join(tempfile.gettempdir(),"my_threatlens_test.db")
try: os.remove(_db_path)
except FileNotFoundError: pass
os.environ["DATABASE_URL"]="sqlite:///"+_db_path.replace("\\","/")
os.environ["LIVE_COLLECTORS_ENABLED"]="false"
os.environ["SHARED_PASSWORD"]="test-only-password"
import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    with TestClient(app) as c:
        username="cyber expert"
        response=c.post("/login",data={"username":username,"password":"test-only-password","next":"/"},follow_redirects=False)
        assert response.status_code==303
        c.test_username=username
        yield c
