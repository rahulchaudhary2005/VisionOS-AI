# Contributing

Thanks for contributing to VisionOS-AI. To keep the project high-quality and consistent, please follow these guidelines:

- Code style: run `ruff --fix` and `black .` before committing. A `pre-commit` config is included.
- Tests: add unit tests under `backend/tests/unit` for new features. Run `pytest` locally.
- Migrations: create Alembic revisions via `python backend/scripts/generate_alembic_revision.py "message"`.
- PRs: open a concise PR with description, testing steps, and link related issues.

See `.github/workflows/ci.yml` for the CI checks that run on PRs.
