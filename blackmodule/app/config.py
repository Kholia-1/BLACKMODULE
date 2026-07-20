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