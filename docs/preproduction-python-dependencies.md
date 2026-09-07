# Préproduction P6 — dépendances Python reproductibles

`requirements.txt` à la racine est l'unique verrou canonique utilisé par le
poste local, les tests et l'image Docker. `blackmodule/requirements.txt` est
conservé uniquement comme point d'entrée compatible et inclut directement le
verrou racine ; il ne contient aucune version indépendante.

Toutes les dépendances directes et transitives sont fixées avec `==`. Les rares
marqueurs concernent uniquement les paquets spécifiques à Windows ou Unix.
`bcrypt==4.0.1` reste volontairement fixé pour sa compatibilité avec
`passlib==1.7.4`. `xlrd` est explicitement conservé pour les imports OFSI `.xls`
et `lxml` pour les traitements XML/écritures optimisées existants.

Le Dockerfile fixe également la version de `pip` et exécute `pip check` pendant
le build. Les images Python et PostgreSQL restent référencées par digest.

## Validation locale propre

Depuis la racine du dépôt :

```powershell
py -3.12 -m venv .venv-p6
.venv-p6\Scripts\python.exe -m pip install pip==26.1.2
.venv-p6\Scripts\python.exe -m pip install -r requirements.txt
.venv-p6\Scripts\python.exe -m pip check
```

Le répertoire temporaire de validation ne doit pas être ajouté au dépôt.

## Limite

Le verrou porte sur Python. Les paquets Debian installés lors du build restent
issus des dépôts Debian attachés à l'image de base ; leur reproductibilité
binaire complète nécessiterait ultérieurement un miroir snapshot interne.
