# Préproduction P5 — logs et supervision

## Journalisation

Les journaux techniques BLACKMODULE sont émis sur la sortie standard au format
JSON. Ils contiennent uniquement des métadonnées techniques autorisées : type
d'événement, route paramétrée, méthode, statut, latence, identifiant de requête,
composant et type d'exception. Les corps, paramètres de requête, en-têtes,
identifiants métier et messages d'exception ne sont pas journalisés.
Le journal d'accès Uvicorn, redondant et fondé sur l'URL concrète, est désactivé ;
le middleware conserve à la place la route paramétrée et non ses valeurs.

`X-Request-ID` accepte au maximum 64 caractères alphanumériques avec `.`, `_` ou
`-`. Une valeur absente ou invalide est remplacée par un UUID. Le même identifiant
est disponible dans le contexte applicatif et renvoyé dans la réponse.

Docker conserve ses journaux avec le pilote `json-file`, 10 Mo par fichier et
5 fichiers par défaut. Les valeurs sont surchargeables avec
`DOCKER_LOG_MAX_SIZE` et `DOCKER_LOG_MAX_FILES`.

## Supervision intégrée

- `/health/live` confirme que le processus répond ;
- `/health/ready` vérifie PostgreSQL ;
- le healthcheck Compose production utilise `/health/ready` ;
- un job interne contrôle périodiquement PostgreSQL et le scheduler ;
- `/health/metrics` expose des agrégats non sensibles et exige
  `X-API-Key` en production.

Les métriques couvrent la disponibilité HTTP observée, les erreurs 5xx, la
latence moyenne/maximale, les requêtes lentes, l'état application/base/scheduler
et le dernier résultat des jobs instrumentés. Une alerte est exposée si un
composant est indisponible ou si au moins 5 erreurs 5xx surviennent en 60 secondes.
Ces seuils sont configurables.

## Limites et intégration future

Les compteurs sont volontairement en mémoire et remis à zéro au redémarrage.
Ils préparent un raccordement ultérieur à un collecteur externe sans imposer
Prometheus ou Grafana dans P5. En environnement multi-réplicas, le collecteur
devra agréger les métriques de chaque processus.
