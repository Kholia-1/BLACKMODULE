from dotenv import load_dotenv
import os

load_dotenv()

BLACKMODULE_ENV = os.getenv("BLACKMODULE_ENV", "development").strip().lower()
IS_PRODUCTION = BLACKMODULE_ENV in {"production", "preproduction", "staging"}


def _required_value(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        raise ValueError(f"{name} doit être défini et non vide.")
    return value.strip()


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().upper().replace("-", "_")
    return (
        "CHANGE_ME" in normalized
        or "CHANGEME" in normalized
        or "BLACKMODULE_PASSWORD" in normalized
    )


def _validate_production_secret(name: str, value: str, minimum_length: int = 32) -> None:
    if not IS_PRODUCTION:
        return
    if _is_placeholder(value):
        raise ValueError(f"{name} contient une valeur d'exemple interdite en production.")
    if len(value) < minimum_length:
        raise ValueError(
            f"{name} doit contenir au moins {minimum_length} caractères en production."
        )


DATABASE_URL = _required_value("DATABASE_URL")
SECRET_KEY = _required_value("SECRET_KEY")
BLACKMODULE_API_KEY = _required_value("BLACKMODULE_API_KEY")

if IS_PRODUCTION:
    if not DATABASE_URL.startswith(("postgresql://", "postgresql+psycopg2://")):
        raise ValueError("DATABASE_URL doit utiliser PostgreSQL en production.")
    if _is_placeholder(DATABASE_URL):
        raise ValueError("DATABASE_URL contient une valeur d'exemple interdite en production.")

_validate_production_secret("SECRET_KEY", SECRET_KEY)
_validate_production_secret("BLACKMODULE_API_KEY", BLACKMODULE_API_KEY)

# Utilisé uniquement lors de l'initialisation d'une base vide. Il ne doit
# jamais avoir de valeur par défaut dans le code ou dans les fichiers d'exemple.
INITIAL_ADMIN_PASSWORD = os.getenv("INITIAL_ADMIN_PASSWORD") or None
if INITIAL_ADMIN_PASSWORD is not None:
    INITIAL_ADMIN_PASSWORD = INITIAL_ADMIN_PASSWORD.strip()
    _validate_production_secret("INITIAL_ADMIN_PASSWORD", INITIAL_ADMIN_PASSWORD, 12)

# En développement local HTTP peut être pratique ; en production cette valeur
# doit impérativement être définie à true.
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true"

SESSION_IDLE_TIMEOUT_MINUTES = int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "15"))
SESSION_ACTIVITY_PERSIST_INTERVAL_MINUTES = int(
    os.getenv("SESSION_ACTIVITY_PERSIST_INTERVAL_MINUTES", "5")
)
MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))

# Durcissement authentification P4. Les valeurs de développement conservent
# la compatibilité historique ; la production impose une politique renforcée.
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "12" if IS_PRODUCTION else "6"))
PASSWORD_MAX_LENGTH = int(os.getenv("PASSWORD_MAX_LENGTH", "128"))
BOOTSTRAP_PASSWORD_TTL_HOURS = int(os.getenv("BOOTSTRAP_PASSWORD_TTL_HOURS", "24"))
LOGIN_RATE_LIMIT_ATTEMPTS = int(os.getenv("LOGIN_RATE_LIMIT_ATTEMPTS", "10"))
LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300"))
SENSITIVE_RATE_LIMIT_ATTEMPTS = int(os.getenv("SENSITIVE_RATE_LIMIT_ATTEMPTS", "120"))
SENSITIVE_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("SENSITIVE_RATE_LIMIT_WINDOW_SECONDS", "60"))
if not 6 <= PASSWORD_MIN_LENGTH <= PASSWORD_MAX_LENGTH <= 256:
    raise ValueError("Configuration de longueur des mots de passe invalide.")
if BOOTSTRAP_PASSWORD_TTL_HOURS <= 0:
    raise ValueError("BOOTSTRAP_PASSWORD_TTL_HOURS doit être strictement positif.")
if min(
    LOGIN_RATE_LIMIT_ATTEMPTS,
    LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    SENSITIVE_RATE_LIMIT_ATTEMPTS,
    SENSITIVE_RATE_LIMIT_WINDOW_SECONDS,
) <= 0:
    raise ValueError("Les paramètres de rate limiting doivent être strictement positifs.")

# Observabilité P5. Les métriques restent internes au processus et n'embarquent
# ni paramètres de requête, ni identifiants métier, ni contenu de réponse.
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip().upper()
if LOG_LEVEL not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
    raise ValueError("LOG_LEVEL invalide.")
MONITORING_ERROR_THRESHOLD = int(os.getenv("MONITORING_ERROR_THRESHOLD", "5"))
MONITORING_ERROR_WINDOW_SECONDS = int(
    os.getenv("MONITORING_ERROR_WINDOW_SECONDS", "60")
)
MONITORING_LATENCY_WARNING_MS = float(
    os.getenv("MONITORING_LATENCY_WARNING_MS", "2000")
)
MONITORING_HEALTHCHECK_INTERVAL_SECONDS = int(
    os.getenv("MONITORING_HEALTHCHECK_INTERVAL_SECONDS", "60")
)
if min(
    MONITORING_ERROR_THRESHOLD,
    MONITORING_ERROR_WINDOW_SECONDS,
    MONITORING_LATENCY_WARNING_MS,
    MONITORING_HEALTHCHECK_INTERVAL_SECONDS,
) <= 0:
    raise ValueError("Les paramètres de supervision P5 doivent être strictement positifs.")

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

# Les actions correctives portent une échéance au jour près. Cette fenêtre
# centralisée pilote le rappel préventif, sans modifier les SLA des alertes.
CORRECTIVE_ACTION_DUE_SOON_HOURS = float(
    os.getenv("CORRECTIVE_ACTION_DUE_SOON_HOURS", "24")
)
if CORRECTIVE_ACTION_DUE_SOON_HOURS <= 0:
    raise ValueError("CORRECTIVE_ACTION_DUE_SOON_HOURS doit être strictement positif.")

# Canal externe facultatif : il reste désactivé tant que l'environnement ne
# l'active pas explicitement. Aucun secret SMTP n'est stocké dans le code.
EMAIL_NOTIFICATIONS_ENABLED = os.getenv("EMAIL_NOTIFICATIONS_ENABLED", "false").lower() == "true"
EMAIL_SMTP_HOST = os.getenv("EMAIL_SMTP_HOST")
EMAIL_SMTP_PORT = int(os.getenv("EMAIL_SMTP_PORT", "587"))
EMAIL_SMTP_USERNAME = os.getenv("EMAIL_SMTP_USERNAME")
EMAIL_SMTP_PASSWORD = os.getenv("EMAIL_SMTP_PASSWORD")
EMAIL_SMTP_FROM = os.getenv("EMAIL_SMTP_FROM")
EMAIL_SMTP_STARTTLS = os.getenv("EMAIL_SMTP_STARTTLS", "true").lower() == "true"
EMAIL_NOTIFICATION_MAX_ATTEMPTS = int(os.getenv("EMAIL_NOTIFICATION_MAX_ATTEMPTS", "3"))
EMAIL_NOTIFICATION_RETRY_MINUTES = int(os.getenv("EMAIL_NOTIFICATION_RETRY_MINUTES", "15"))
if EMAIL_SMTP_PORT <= 0:
    raise ValueError("EMAIL_SMTP_PORT doit être strictement positif.")
if EMAIL_NOTIFICATION_MAX_ATTEMPTS <= 0:
    raise ValueError("EMAIL_NOTIFICATION_MAX_ATTEMPTS doit être strictement positif.")
if EMAIL_NOTIFICATION_RETRY_MINUTES <= 0:
    raise ValueError("EMAIL_NOTIFICATION_RETRY_MINUTES doit être strictement positif.")
