from logging.config import fileConfig
import os
from pathlib import Path
import sys

from alembic import context
from sqlalchemy import engine_from_config, pool

# Le dépôt stocke l'application sous blackmodule/app tandis que l'image la
# copie sous /code/app. Résoudre explicitement les deux dispositions sans
# dépendre du répertoire courant de la commande Alembic.
for candidate in (Path(__file__).resolve().parents[1], Path(__file__).resolve().parents[2]):
    if (candidate / "app").is_dir():
        sys.path.insert(0, str(candidate))
        break

from app.database import Base
from app import models  # noqa: F401 - enregistre tous les modèles dans Base.metadata


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

database_url = os.getenv("DATABASE_URL")
if not database_url or not database_url.strip():
    raise RuntimeError("DATABASE_URL doit être défini pour exécuter Alembic.")
config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))

target_metadata = Base.metadata


def include_object(obj, name, type_, reflected, compare_to):
    # Les index de performance LOT 0A/2C sont administrés explicitement par
    # migration/SQL. Ils doivent être conservés même s'ils ne sont pas tous
    # déclarés dans les modèles SQLAlchemy.
    if type_ == "index" and reflected and compare_to is None:
        return False
    return True


def run_migrations_offline():
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            include_object=include_object,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
