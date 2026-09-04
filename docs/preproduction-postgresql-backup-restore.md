# Sauvegarde et recette de restauration PostgreSQL

Cette procédure concerne la préproduction BLACKMODULE. Elle ne remplace pas
une stratégie PITR/WAL ni une copie chiffrée hors du serveur Docker.

## Préparation unique

Créer le volume externe de sauvegarde, distinct du volume PostgreSQL :

```bash
docker volume create blackmodule_postgres_backups
```

Conserver les variables PostgreSQL et les secrets dans un fichier protégé hors
du dépôt. Ne jamais passer le mot de passe directement dans la ligne de commande.

## Créer et contrôler une sauvegarde

```bash
docker compose --env-file /chemin/securise/blackmodule.env \
  -f docker-compose.prod.yml --profile database-tools run --rm db-tools \
  /opt/blackmodule/scripts/postgres_backup.sh
```

Le script crée un fichier UTC `BASE_AAAAMMJJTHHMMSSZ.dump`, vérifie son catalogue
avec `pg_restore --list`, puis produit un fichier SHA-256 associé. La rétention
est définie par `BACKUP_RETENTION_DAYS` et vaut 14 jours par défaut.

## Tester une restauration

Choisir le fichier annoncé par `BACKUP_FILE`. La cible doit être une base
inexistante, distincte de la source, et porter le suffixe `_restore_test`.

```bash
docker compose --env-file /chemin/securise/blackmodule.env \
  -f docker-compose.prod.yml --profile database-tools run --rm \
  -e BACKUP_FILE=/backups/blackmodule_AAAAMMJJTHHMMSSZ.dump \
  -e RESTORE_TARGET_DATABASE=blackmodule_restore_test db-tools \
  /opt/blackmodule/scripts/postgres_restore_test.sh
```

Le script vérifie le checksum et le catalogue avant création de la base. Il
compare ensuite les volumes des tables critiques `users`, `sanction_entries`,
`alerts`, `import_batches` et `approval_requests`. Une restauration incomplète
est supprimée automatiquement ; une restauration valide reste disponible pour
les contrôles fonctionnels complémentaires et doit être supprimée uniquement
par un administrateur PostgreSQL après validation.

## Contrôles périodiques

- exécuter une sauvegarde selon le RPO retenu ;
- tester une restauration sur une base distincte au minimum mensuellement ;
- relever le checksum, la taille, la durée et le résultat du test ;
- copier les sauvegardes vers un stockage chiffré hors du serveur Docker ;
- surveiller l’espace disponible et les échecs du job.
