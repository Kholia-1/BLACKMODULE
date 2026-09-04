# Durcissement sécurité de préproduction

## Identifiant bootstrap

En production, le compte `admin` créé depuis `INITIAL_ADMIN_PASSWORD` est
limité à la page de changement de mot de passe. Son secret initial expire au
bout de 24 heures par défaut. Après remplacement, le hash est renouvelé,
l'obligation et l'échéance bootstrap sont supprimées et la date de changement
est enregistrée. La valeur d'environnement initiale ne permet alors plus de se
connecter et doit être retirée du gestionnaire de secrets du déploiement.

Si l'échéance expire avant le premier changement, une réinitialisation
administrative contrôlée est nécessaire ; aucun contournement Web n'est prévu.

## Exposition et limites

- `/docs`, `/redoc`, `/openapi.json` et `/db-check` ne sont pas exposés en
  production. Les sondes supportées restent `/health/live` et `/health/ready`.
- Les tentatives de connexion sont limitées à 10 sur 5 minutes par processus et
  adresse cliente. Les API externes et opérations sensibles sont limitées à
  120 requêtes par minute.
- Le limiteur intégré est adapté à une instance pilote. Avec plusieurs réplicas,
  un stockage partagé de compteurs devra être ajouté pour une limite globale.
- Les refus sont audités avec l'utilisateur, le chemin et l'adresse cliente,
  sans mot de passe, clé API ni contenu de requête.
