import os
import sys
from pathlib import Path
import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Compute project root and ensure `backend` is on sys.path so imports like
# `import app.*` resolve when pytest runs from the `backend` folder.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

os.environ.setdefault("SECRET_KEY", "test_secret_key")
os.environ.setdefault("JWT_SECRET", "test_jwt_secret")

# Use a temporary file-backed SQLite DB for tests so multiple connections
# (TestClient, SQLAlchemy sessions) share the same database. Clean up
# the file at process exit.
import tempfile
import atexit

_tmp_db = tempfile.NamedTemporaryFile(
    prefix="visionos_test_", suffix=".db", delete=False
)
_tmp_db_path = _tmp_db.name
_tmp_db.close()
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp_db_path.replace('\\', '/')}")
os.environ.setdefault("OLLAMA_URL", "http://localhost")


def _cleanup_test_db():
    try:
        import os as _os

        _os.unlink(_tmp_db_path)
    except Exception:
        pass


atexit.register(_cleanup_test_db)

from app.api.dependencies.database import get_db as get_db_dependency  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.database.database import engine  # noqa: E402
from main import app  # noqa: E402

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db_dependency] = override_get_db


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as client_instance:
        yield client_instance
