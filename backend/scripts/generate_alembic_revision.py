#!/usr/bin/env python3
"""Generate an Alembic autogenerate revision using the app settings.

Usage:
    python scripts/generate_alembic_revision.py "message for revision"

This script sets the alembic config's sqlalchemy.url from app settings
and calls alembic.command.revision(autogenerate=True).
"""

from __future__ import annotations

import sys
from pathlib import Path

from alembic.config import Config
from alembic import command

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from app.config.settings import settings  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    message = argv[0] if argv else "autogen migration"

    alembic_ini = HERE / "alembic.ini"
    cfg = Config(str(alembic_ini))

    # Ensure alembic uses the application's configured DB URL
    cfg.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

    print("Generating revision (autogenerate) with message:", message)
    command.revision(cfg, message=message, autogenerate=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
