# Reverse proxy pilote BLACKMODULE

Le reverse proxy gere par l'infrastructure termine TLS et transmet les requetes
vers `127.0.0.1:10000`. `PUBLIC_HOSTNAME` doit contenir le nom DNS public exact.
`FORWARDED_ALLOW_IPS` doit contenir uniquement l'adresse IP ou les CIDR exacts
depuis lesquels Uvicorn voit le proxy. La valeur `*` et les reseaux universels
sont refuses en production.

Le proxy doit remplacer, et non concatener aveuglement, `X-Forwarded-For`,
`X-Forwarded-Proto` et `X-Forwarded-Host`. Le trafic direct vers le port 10000
reste limite a la boucle locale. Les certificats et la redirection HTTP vers
HTTPS restent sous la responsabilite de l'infrastructure et hors du conteneur
applicatif.

## Filtrage des endpoints techniques

- `/health/live` : autoriser uniquement les sondes internes ;
- `/health/ready` : autoriser uniquement les sondes internes ;
- `/health/metrics` : autoriser uniquement le collecteur interne et conserver
  l'authentification `X-API-Key` ;
- `/db-check`, `/docs`, `/redoc` et `/openapi.json` : restent indisponibles en
  production.

Le reverse proxy ne doit pas exposer publiquement les trois routes `/health/*`.
Le healthcheck Docker fournit le `Host` public attendu sans passer par TLS ; ce
trafic reste strictement interne au conteneur.
