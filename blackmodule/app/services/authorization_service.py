"""Rôles et permissions centralisés de BLACKMODULE.

Les routes ne doivent jamais déduire une permission depuis un nom de rôle.
Cette matrice est l'unique source de vérité applicative.
"""

from __future__ import annotations

ROLE_ADMIN_TECHNIQUE = "ADMIN_TECHNIQUE"
ROLE_SUPERVISEUR_CONFORMITE = "SUPERVISEUR_CONFORMITE"
ROLE_ANALYSTE_CONFORMITE = "ANALYSTE_CONFORMITE"
ROLE_GESTIONNAIRE_LISTES = "GESTIONNAIRE_LISTES"
ROLE_CONSULTATION = "CONSULTATION"
ROLE_AUDITEUR = "AUDITEUR"

ALL_ROLES = {
    ROLE_ADMIN_TECHNIQUE,
    ROLE_SUPERVISEUR_CONFORMITE,
    ROLE_ANALYSTE_CONFORMITE,
    ROLE_GESTIONNAIRE_LISTES,
    ROLE_CONSULTATION,
    ROLE_AUDITEUR,
}

LEGACY_ROLE_MAP = {
    "ADMIN": ROLE_ADMIN_TECHNIQUE,
    "SUPERVISEUR": ROLE_SUPERVISEUR_CONFORMITE,
    "OPERATEUR": ROLE_ANALYSTE_CONFORMITE,
    "LECTEUR": ROLE_CONSULTATION,
}

PERMISSION_USERS_MANAGE = "USERS_MANAGE"
PERMISSION_USERS_VIEW = "USERS_VIEW"
PERMISSION_SANCTIONS_VIEW = "SANCTIONS_VIEW"
PERMISSION_LISTS_VIEW = "LISTS_VIEW"
PERMISSION_LISTS_IMPORT = "LISTS_IMPORT"
PERMISSION_LISTS_MANAGE = "LISTS_MANAGE"
PERMISSION_ALERTS_VIEW = "ALERTS_VIEW"
PERMISSION_ALERTS_TREAT = "ALERTS_TREAT"
PERMISSION_ALERTS_CONFIRM = "ALERTS_CONFIRM"
PERMISSION_ALERTS_CLOSE = "ALERTS_CLOSE"
PERMISSION_MATCHING_SETTINGS_VIEW = "MATCHING_SETTINGS_VIEW"
PERMISSION_MATCHING_SETTINGS_CHANGE = "MATCHING_SETTINGS_CHANGE"
PERMISSION_APPROVAL_VALIDATE = "APPROVAL_VALIDATE"
PERMISSION_AUDIT_VIEW = "AUDIT_VIEW"
PERMISSION_NOTIFICATIONS_VIEW = "NOTIFICATIONS_VIEW"
PERMISSION_EXPORT_USERS = "EXPORT_USERS"
PERMISSION_EXPORT_AUDIT = "EXPORT_AUDIT"

# Aliases conservés pour les routes déjà nommées dans l'application.
PERMISSION_MANAGE_USERS = PERMISSION_USERS_MANAGE
PERMISSION_MANAGE_TECHNICAL_CONFIGURATION = "MANAGE_TECHNICAL_CONFIGURATION"
PERMISSION_VIEW_AUDIT = PERMISSION_AUDIT_VIEW
PERMISSION_MANAGE_LISTS = PERMISSION_LISTS_MANAGE
PERMISSION_VIEW_LISTS = PERMISSION_LISTS_VIEW
PERMISSION_SCREEN_CLIENT = "SCREEN_CLIENT"
PERMISSION_VIEW_ALERTS = PERMISSION_ALERTS_VIEW
PERMISSION_TREAT_ALERTS = PERMISSION_ALERTS_TREAT
PERMISSION_VIEW_CRITICAL_ALERTS = "VIEW_CRITICAL_ALERTS"
PERMISSION_MANAGE_MATCHING_SETTINGS = PERMISSION_MATCHING_SETTINGS_CHANGE
PERMISSION_REVIEW_FOUR_EYES = PERMISSION_APPROVAL_VALIDATE
PERMISSION_VIEW_APPROVALS = "VIEW_APPROVALS"
PERMISSION_EXPORT_DATA = PERMISSION_EXPORT_AUDIT

ROLE_PERMISSIONS = {
    ROLE_ADMIN_TECHNIQUE: {
        PERMISSION_MANAGE_USERS,
        PERMISSION_USERS_VIEW,
        PERMISSION_SANCTIONS_VIEW,
        PERMISSION_LISTS_VIEW,
        # TEMPORAIRE développement/recette : à retirer lorsque
        # GESTIONNAIRE_LISTES sera opérationnel en production.
        PERMISSION_LISTS_IMPORT,
        PERMISSION_MANAGE_LISTS,
        PERMISSION_VIEW_ALERTS,
        PERMISSION_VIEW_CRITICAL_ALERTS,
        PERMISSION_NOTIFICATIONS_VIEW,
        PERMISSION_MANAGE_TECHNICAL_CONFIGURATION,
        PERMISSION_VIEW_AUDIT,
        PERMISSION_VIEW_APPROVALS,
        PERMISSION_EXPORT_USERS,
        PERMISSION_EXPORT_AUDIT,
    },
    ROLE_SUPERVISEUR_CONFORMITE: {
        PERMISSION_SANCTIONS_VIEW,
        PERMISSION_VIEW_LISTS,
        PERMISSION_MATCHING_SETTINGS_VIEW,
        PERMISSION_SCREEN_CLIENT,
        PERMISSION_VIEW_ALERTS,
        PERMISSION_NOTIFICATIONS_VIEW,
        PERMISSION_TREAT_ALERTS,
        PERMISSION_ALERTS_CONFIRM,
        PERMISSION_ALERTS_CLOSE,
        PERMISSION_VIEW_CRITICAL_ALERTS,
        PERMISSION_MANAGE_MATCHING_SETTINGS,
        PERMISSION_REVIEW_FOUR_EYES,
        PERMISSION_VIEW_APPROVALS,
        PERMISSION_VIEW_AUDIT,
        PERMISSION_EXPORT_AUDIT,
    },
    ROLE_ANALYSTE_CONFORMITE: {
        PERMISSION_SANCTIONS_VIEW,
        PERMISSION_VIEW_LISTS,
        PERMISSION_SCREEN_CLIENT,
        PERMISSION_VIEW_ALERTS,
        PERMISSION_NOTIFICATIONS_VIEW,
        PERMISSION_TREAT_ALERTS,
    },
    ROLE_GESTIONNAIRE_LISTES: {
        PERMISSION_MANAGE_LISTS,
        PERMISSION_LISTS_IMPORT,
        PERMISSION_VIEW_LISTS,
        PERMISSION_SANCTIONS_VIEW,
    },
    ROLE_CONSULTATION: {
        PERMISSION_VIEW_LISTS,
        PERMISSION_SANCTIONS_VIEW,
        PERMISSION_VIEW_ALERTS,
    },
    ROLE_AUDITEUR: {
        PERMISSION_VIEW_AUDIT,
        PERMISSION_VIEW_APPROVALS,
        PERMISSION_EXPORT_AUDIT,
    },
}


def canonical_role(role: str | None) -> str:
    normalized = (role or "").upper()
    return LEGACY_ROLE_MAP.get(normalized, normalized)


def permissions_for_role(role: str | None) -> set[str]:
    return set(ROLE_PERMISSIONS.get(canonical_role(role), set()))


def refresh_session_user(user: dict | None) -> dict | None:
    """Refresh a session payload from the central RBAC matrix.

    Browser sessions can survive a deployment. Their embedded permissions
    must therefore never override the permissions currently assigned to the
    role in this module.
    """
    if not user:
        return None

    role = canonical_role(user.get("role"))
    return {
        **user,
        "role": role,
        "role_label": role_label(role),
        "permissions": sorted(permissions_for_role(role)),
    }


ROLE_LABELS = {
    ROLE_ADMIN_TECHNIQUE: "Administrateur technique",
    ROLE_SUPERVISEUR_CONFORMITE: "Superviseur conformité",
    ROLE_ANALYSTE_CONFORMITE: "Analyste conformité",
    ROLE_GESTIONNAIRE_LISTES: "Gestionnaire des listes",
    ROLE_CONSULTATION: "Consultation",
    ROLE_AUDITEUR: "Auditeur",
}


def role_label(role: str | None) -> str:
    canonical = canonical_role(role)
    return ROLE_LABELS.get(canonical, canonical or "Non connecté")


def has_permission(user: dict | None, permission: str) -> bool:
    if not user:
        return False
    permissions = user.get("permissions")
    if permissions is not None:
        return permission in permissions
    return permission in permissions_for_role(user.get("role"))


def session_user_payload(user) -> dict:
    role = canonical_role(user.role)
    return refresh_session_user({
        "id": str(user.id),
        "username": user.username,
        "full_name": user.full_name,
        "role": role,
    })
