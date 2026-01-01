-- =============================================================================
-- FROM 00000000000000_schema setup.sql
-- =============================================================================
--
-- This migration transitions to a zone-based least-privilege security model in
-- accordance with the associated ADR. It is idempotent (can be rerun safely).
-- The most recent version of this migration should always be the same as the
-- schema setup sql file in the supabase/schemas directory.

-- =============================================================================
-- DEFAULT EXECUTE PRIVILEGE
-- Remove default privileges for ROUTINES created by postgres user
-- This seems to be necessary if default privileges in schemas are additive; 
-- you can't revoke a default privilege that is granted at a higher level.
-- =============================================================================
ALTER DEFAULT PRIVILEGES FOR ROLE postgres 
REVOKE EXECUTE ON ROUTINES FROM public;

-- =============================================================================
-- SET SEARCH PATH FOR ROLES
-- =============================================================================
ALTER ROLE anon SET search_path = api;
ALTER ROLE authenticated SET search_path = api;
ALTER ROLE service_role SET search_path = api, private;
ALTER ROLE postgres SET search_path = api, private;

-- =============================================================================
-- API SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS api;
ALTER SCHEMA "api" OWNER TO "postgres";

-- Usage
REVOKE ALL ON SCHEMA api FROM public;
GRANT USAGE ON SCHEMA api TO anon, authenticated, service_role;

-- Default privileges for TABLES (and views)

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA api
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO anon, authenticated, service_role;

-- Default privileges for SEQUENCES

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA api
GRANT USAGE, SELECT ON SEQUENCES TO anon, authenticated, service_role;

-- Default privileges for ROUTINES

REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA api FROM public;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA api
REVOKE EXECUTE ON ROUTINES FROM public;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA api
GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;

-- Default privileges for TYPES

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA api
GRANT USAGE ON TYPES TO anon, authenticated, service_role;

-- Documentation

COMMENT ON SCHEMA api IS
  'Application schema for Ocean/WholeReader tables and views (publicly readable via RLS). ROUTINES are in private schema.';

-- =============================================================================
-- PRIVATE SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS private;
ALTER SCHEMA "private" OWNER TO "postgres";

-- Usage
REVOKE ALL ON SCHEMA private FROM public;
GRANT USAGE ON SCHEMA private TO service_role;

-- Default privileges for TABLES (and views)

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA private
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO service_role;

-- Default privileges for SEQUENCES

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA private
GRANT USAGE, SELECT ON SEQUENCES TO service_role;

-- Default privileges for ROUTINES

REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA private FROM public;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA private
REVOKE EXECUTE ON ROUTINES FROM public;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA private
GRANT EXECUTE ON ROUTINES TO service_role;

-- Default privileges for TYPES

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA private
GRANT USAGE ON TYPES TO service_role;

-- Documentation

COMMENT ON SCHEMA private IS
  'Internal ROUTINES schema (NOT exposed via PostgREST). Only service_role can execute. Used for triggers, cron jobs, and admin operations.';
