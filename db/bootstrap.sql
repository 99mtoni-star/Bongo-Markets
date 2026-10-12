-- Bongo Markets: one-time database and role bootstrap (run by the DBA as a superuser).
--
--   psql "$ADMIN_URL" -v ON_ERROR_STOP=1 \
--        -v db_name=bongomarkets \
--        -v owner_role=bm_owner -v owner_pw="$OWNER_PW" \
--        -v app_role=bm_app     -v app_pw="$APP_PW" \
--        -v ro_role=bm_readonly -v ro_pw="$RO_PW" \
--        -f db/bootstrap.sql
--
-- Roles (SEC-005, least privilege):
--   owner_role : owns schema "bm"; used ONLY to run migrations. Never used by the app.
--   app_role   : the running application. DML on business tables only, no DDL,
--                INSERT/SELECT only on audit tables (SEC-AUD-001).
--   ro_role    : reporting/support read-only access.
-- Production uses a dedicated PostgreSQL instance for Bongo Markets only (SEC-DB-006).

\set ON_ERROR_STOP on

CREATE ROLE :"owner_role" LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE :"app_role"   LOGIN PASSWORD :'app_pw'   NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE :"ro_role"    LOGIN PASSWORD :'ro_pw'    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

CREATE DATABASE :"db_name" OWNER :"owner_role" ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db_name" TO :"app_role", :"ro_role";
-- No role may create temporary objects except the owner.
GRANT TEMPORARY ON DATABASE :"db_name" TO :"owner_role";

\connect :"db_name"

REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA bm AUTHORIZATION :"owner_role";
REVOKE ALL ON SCHEMA bm FROM PUBLIC;
GRANT USAGE ON SCHEMA bm TO :"app_role", :"ro_role";

-- Every table/sequence the owner creates later gets these grants automatically.
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_role" IN SCHEMA bm
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_role" IN SCHEMA bm
    GRANT USAGE, SELECT ON SEQUENCES TO :"app_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_role" IN SCHEMA bm
    GRANT SELECT ON TABLES TO :"ro_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_role" IN SCHEMA bm
    GRANT EXECUTE ON FUNCTIONS TO :"app_role";

ALTER ROLE :"owner_role" IN DATABASE :"db_name" SET search_path = bm;
ALTER ROLE :"app_role"   IN DATABASE :"db_name" SET search_path = bm;
ALTER ROLE :"ro_role"    IN DATABASE :"db_name" SET search_path = bm;
ALTER ROLE :"ro_role"    IN DATABASE :"db_name" SET default_transaction_read_only = on;
