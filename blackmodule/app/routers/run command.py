Lancement local
python -m uvicorn app.main:app --reload


Lancement sur le réseau
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000


API externe

Endpoints principaux :

GET /api/external/status
GET /api/external/documentation
POST /api/external/check-client
GET /api/external/alerts/{client_reference}

Toutes les requêtes externes doivent contenir le header :

X-API-KEY: votre_cle_api