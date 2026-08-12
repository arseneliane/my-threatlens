import os, tempfile
_db_path=os.path.join(tempfile.gettempdir(),"my_threatlens_test.db")
try: os.remove(_db_path)
except FileNotFoundError: pass
os.environ["DATABASE_URL"]="sqlite:///"+_db_path.replace("\\","/")
os.environ["LIVE_COLLECTORS_ENABLED"]="false"
import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    with TestClient(app) as c: yield c
