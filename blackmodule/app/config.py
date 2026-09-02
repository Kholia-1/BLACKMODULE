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

# A source update is blocked before any mutation when its parsed active volume
# drops by more than this percentage compared with the current version.
LIST_MAX_ENTRY_DROP_PERCENT = float(os.getenv("LIST_MAX_ENTRY_DROP_PERCENT", "30"))
if not 0 <= LIST_MAX_ENTRY_DROP_PERCENT < 100:
    raise ValueError("LIST_MAX_ENTRY_DROP_PERCENT doit être compris entre 0 et 100.")

# CSV/XLSX internal-list uploads are parsed in memory. Keep a central ceiling
# to prevent an authenticated upload from exhausting the application process.
INTERNAL_LIST_IMPORT_MAX_BYTES = int(
    os.getenv("INTERNAL_LIST_IMPORT_MAX_BYTES", str(25 * 1024 * 1024))
)
if INTERNAL_LIST_IMPORT_MAX_BYTES <= 0:
    raise ValueError("INTERNAL_LIST_IMPORT_MAX_BYTES doit être strictement positif.")

# SLA de traitement des alertes, centralisés et surchargeables par environnement.
ALERT_SLA_HOURS = {
    "ALERTE_EXACTE": float(os.getenv("ALERT_SLA_EXACT_HOURS", "4")),
    "ALERTE_PROBABLE": float(os.getenv("ALERT_SLA_PROBABLE_HOURS", "24")),
    "ALERTE_POSSIBLE": float(os.getenv("ALERT_SLA_POSSIBLE_HOURS", "72")),
}
if any(hours <= 0 for hours in ALERT_SLA_HOURS.values()):
    raise ValueError("Les SLA d'alertes doivent être strictement positifs.")

ALERT_SLA_NEAR_RATIO = float(os.getenv("ALERT_SLA_NEAR_RATIO", "0.8"))
if not 0 < ALERT_SLA_NEAR_RATIO < 1:
    raise ValueError("ALERT_SLA_NEAR_RATIO doit être compris entre 0 et 1.")

ALERT_INACTIVITY_HOURS = float(os.getenv("ALERT_INACTIVITY_HOURS", "24"))
if ALERT_INACTIVITY_HOURS <= 0:
    raise ValueError("ALERT_INACTIVITY_HOURS doit être strictement positif.")
