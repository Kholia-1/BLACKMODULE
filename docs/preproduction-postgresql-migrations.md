# Migrations PostgreSQL de préproduction

BLACKMODULE utilise Alembic comme unique mécanisme de migration contrôlée en
préproduction et production. Le démarrage applicatif refuse un schéma qui
n'est pas à la révision attendue ; il ne crée ni table, ni colonne, ni index.

## Procédure d'upgrade

1. Créer et contrôler une sauvegarde PostgreSQL avec la procédure P2.
2. Vérifier la configuration sans l'afficher :
   `docker compose -f docker-compose.prod.yml config --quiet`.
3. Appliquer la migration avec un compte propriétaire du schéma :
   `docker compose -f docker-compose.prod.yml --profile database-migration run --rm migrate upgrade head`.
4. Contrôler la révision :
   `docker compose -f docker-compose.prod.yml --profile database-migration run --rm migrate current`.
5. Démarrer ou recréer uniquement l'application BLACKMODULE puis contrôler
   `/health/live` et `/health/ready`.

Le rôle de migration doit pouvoir créer les extensions `pg_trgm` et
`unaccent`. Le rôle d'exécution de l'application n'a pas besoin de ce droit.

## Test et rollback

Toute migration est d'abord exécutée sur une restauration distincte de la
base. La migration de référence `p3_0001_current_schema` est non destructive.
Son `downgrade base` enlève le marquage Alembic sans supprimer le schéma ni les
données ; un nouvel `upgrade head` le réadopte de façon idempotente.

Ce rollback de référence ne revient donc pas à une ancienne structure. Un
retour applicatif nécessite l'image Docker précédente et la sauvegarde P2.
Les migrations futures devront fournir un downgrade explicite uniquement
lorsqu'il peut préserver les données ; sinon la restauration P2 est requise.
