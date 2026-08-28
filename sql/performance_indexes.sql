-- LOT 0A - indexes for the current BLACKMODULE query paths.
-- Run once against the existing PostgreSQL database. This script does not
-- alter or delete data and may be safely re-run.

CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS unaccent;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sanction_entries_source_statut_created
    ON sanction_entries (source_liste, statut, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sanction_entries_statut_created
    ON sanction_entries (statut, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sanction_entries_birth_date
    ON sanction_entries (date_naissance)
    WHERE date_naissance IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sanction_entries_passport_upper
    ON sanction_entries (upper(num_passeport))
    WHERE num_passeport IS NOT NULL;

-- LOT 2C deterministic duplicate checks for internal records.  These are
-- deliberately non-unique: existing data is never merged or deleted by an
-- index migration, and the service reports candidates for human review.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_internal_source_reference_upper
    ON sanction_entries (source_liste, upper(source_reference))
    WHERE is_internal_list AND source_reference IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_internal_document_number_upper
    ON sanction_entries (upper(document_number))
    WHERE is_internal_list AND document_number IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_internal_name_birth_date
    ON sanction_entries (upper(nom), date_naissance)
    WHERE is_internal_list AND date_naissance IS NOT NULL;

-- Supports ILIKE '%token%' used by the sanctions search and matching
-- candidate preselection.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sanction_entries_nom_trgm
    ON sanction_entries USING gin (nom gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sanction_entries_prenom_trgm
    ON sanction_entries USING gin (prenom gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sanction_entries_nom_complet_trgm
    ON sanction_entries USING gin (nom_complet gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sanction_aliases_alias_trgm
    ON sanction_aliases USING gin (alias gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sanction_aliases_entry_id
    ON sanction_aliases (sanction_entry_id);

-- Supports duplicate-alert checks performed after a match.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_client_sanction_type_status
    ON alerts (client_reference, sanction_entry_id, matching_type, statut);
