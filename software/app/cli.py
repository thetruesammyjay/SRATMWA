"""CLI entry points for SRATMWA.

Registered in pyproject.toml [project.scripts]:
    init  →  app.cli:init   (initialise DB + seed starter data)
    dev   →  app.cli:dev    (start the Flask development server)
"""


def init() -> None:
    """Initialise the database and populate it with starter data."""
    # seed.py lives at the project root (software/), which is on sys.path
    # when the package is installed in editable mode via `uv sync`.
    from seed import seed  # noqa: PLC0415

    print("Initialising SRATMWA database…\n")
    seed()


def dev() -> None:
    """Start the Flask development server on http://127.0.0.1:5000."""
    from app import create_app, db  # noqa: PLC0415

    application = create_app()
    with application.app_context():
        db.create_all()
    application.run(debug=True, host="127.0.0.1", port=5000)
