# BLACKMODULE

Stack :

- FastAPI
- SQLAlchemy
- PostgreSQL
- Jinja2
- Docker

## Règles de développement

- Inspecter le code existant avant de modifier.
- Réutiliser l'architecture existante.
- Ne pas créer d'architecture parallèle inutile.
- Toute modification doit préserver les fonctionnalités existantes.
- Ajouter des tests pour chaque correction fonctionnelle.
- Exécuter compileall et les tests de régression.
- Exécuter git diff --check avant commit.

## Base de données

- Aucune migration destructive sans autorisation explicite.
- Aucun DROP TABLE.
- Aucun TRUNCATE.
- Ne supprimer aucune donnée existante.
- Les migrations doivent être idempotentes.
- Tester les migrations sur PostgreSQL local avant production.

## Sécurité

- Ne jamais écrire password, password_hash, token, secret ou API key dans logs/audit.
- Protéger les permissions côté backend, pas seulement dans les templates.
- Respecter le principe du moindre privilège.
- Respecter le principe des quatre yeux lorsque requis.

## Infrastructure

- Ne jamais modifier Nginx.
- Ne jamais modifier systemd.
- Ne jamais modifier le réseau ou les ports du serveur.
- Ne jamais arrêter d'autres applications du serveur.
- Ne jamais modifier la swap ou les paramètres système.
- Les changements infrastructure appartiennent à l'équipe habilitée de la banque.

## Git / Déploiement

Sauf demande explicite :

- ne pas commit ;
- ne pas push ;
- ne pas déployer ;
- ne pas accéder à la production.

Avant production :

- sauvegarde PostgreSQL ;
- image Docker rollback ;
- health checks ;
- procédure de rollback préparée.

## LOT 0A à préserver

Ne pas casser :

- présélection SQL des candidats ;
- pg_trgm / unaccent ;
- pagination sanctions ;
- export XLSX write_only ;
- yield_per ;
- fichiers temporaires d'export ;
- /health/live ;
- /health/ready ;
- slow operation logging.

## LOT 1A à préserver

Ne pas casser :

- verrouillage après 5 échecs ;
- nouveaux rôles RBAC ;
- permissions centralisées ;
- séparation ADMIN_TECHNIQUE / conformité ;
- validations quatre yeux ;
- timeout session 15 minutes ;
- audit VIEW_SANCTION_DETAIL ;
- approval_requests.

## Réponse attendue après une tâche

Toujours donner :

1. fichiers modifiés ;
2. résumé des changements ;
3. tests exécutés ;
4. résultat des tests ;
5. risques ou limites ;
6. git diff --stat ;
7. git status --short.
