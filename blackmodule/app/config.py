from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL is None:
    raise ValueError("DATABASE_URL n'est pas défini dans le fichier .env")

SECRET_KEY = os.getenv("SECRET_KEY")

if SECRET_KEY is None:
    raise ValueError("SECRET_KEY n'est pas défini dans le fichier .env")

BLACKMODULE_API_KEY = os.getenv("BLACKMODULE_API_KEY")

if BLACKMODULE_API_KEY is None:
    raise ValueError("BLACKMODULE_API_KEY n'est pas défini dans le fichier .env")

# Utilisé uniquement lors de l'initialisation d'une base vide. Il ne doit
# jamais avoir de valeur par défaut dans le code ou dans les fichiers d'exemple.
INITIAL_ADMIN_PASSWORD = os.getenv("INITIAL_ADMIN_PASSWORD")

# En développement local HTTP peut être pratique ; en production cette valeur
# doit impérativement être définie à true.
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true"

SESSION_IDLE_TIMEOUT_MINUTES = int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "15"))
SESSION_ACTIVITY_PERSIST_INTERVAL_MINUTES = int(
    os.getenv("SESSION_ACTIVITY_PERSIST_INTERVAL_MINUTES", "5")
)
MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
