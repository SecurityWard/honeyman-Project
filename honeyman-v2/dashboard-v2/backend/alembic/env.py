"""
Alembic migration environment.

Notes:
- V2 has no `users` table; do not import a User model here.
- The runtime backend uses asyncpg, but Alembic uses a synchronous engine.
  We rewrite the DATABASE_URL driver to psycopg2 for migrations only.
  psycopg2-binary is already in requirements.txt.
"""

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import sys
import os

# Add parent directory to path so `app.*` imports resolve
sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), '..')))

from app.db.base import Base
from app.models.sensor import Sensor      # noqa: F401  (register table with Base.metadata)
from app.models.threat import Threat      # noqa: F401  (register table with Base.metadata)
from app.core.config import settings

# Alembic Config object
config = context.config

# Set SQLAlchemy URL from settings, swapping the async driver for the sync one.
# Runtime: postgresql+asyncpg://...   →   Migrations: postgresql://... (psycopg2)
config.set_main_option(
    "sqlalchemy.url",
    settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://"),
)

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode"""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode"""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
