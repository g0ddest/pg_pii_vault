-- pg_pii_vault 0.0.0 -> 0.1.0
--
-- Behaviour changes (see CHANGELOG.md):
--  * decryption (piitext_out_text, value::text) is STABLE instead of IMMUTABLE,
--    encryption is VOLATILE; indexes, generated columns, materialized views
--    and extended statistics built on decrypted values under 0.0.x still
--    contain plaintext (a WARNING lists them below) and must be dropped by
--    the administrator; indexes and generated columns on the other formerly
--    IMMUTABLE functions are reported too, as their dumps cannot be restored;
--  * the implicit text -> piitext cast is gone (writing text into a piitext
--    column now fails instead of silently storing plaintext) and
--    piitext -> text is an explicit cast;
--  * plaintext staging values are refused everywhere (piitext_in_text() and
--    the type's input functions) while pii_vault.allow_staging is off;
--  * decrypting, encrypting and administrative functions are no longer
--    executable by PUBLIC: GRANT EXECUTE them to the roles that need them;
--  * a NULL key id passed to piitext_encrypt*() raises an error instead of
--    silently returning NULL.
-- Stored values need no migration: 0.1.0 reads the 0.0.x on-disk format.

\echo Use "ALTER EXTENSION pg_pii_vault UPDATE TO '0.1.0'" to load this file. \quit

DO $$
BEGIN
    IF pg_catalog.getdatabaseencoding() <> 'UTF8' THEN
        RAISE WARNING 'pg_pii_vault requires a UTF8 database; this database uses %: non-ASCII values will fail',
            pg_catalog.getdatabaseencoding();
    END IF;
END
$$;

-- Report objects that persist decrypted values: indexes, stored generated
-- columns, materialized views and extended statistics on a decrypting
-- expression. A stored generated column depends on the function through its
-- default expression (PostgreSQL 16 and later) or through the column itself
-- (PostgreSQL 14 and 15, automatic dependency).
DO $$
DECLARE
    dep record;
BEGIN
    FOR dep IN
        SELECT DISTINCT pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid) AS what
        FROM pg_catalog.pg_depend d
        WHERE d.refclassid = 'pg_catalog.pg_proc'::pg_catalog.regclass
          AND d.refobjid = 'piitext_out_text(piitext)'::pg_catalog.regprocedure
          AND d.deptype IN ('n', 'a')
          AND ((d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                AND (d.objsubid = 0
                     OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
                                WHERE a.attrelid = d.objid AND a.attnum = d.objsubid
                                  AND a.attgenerated <> '')))
               OR d.classid IN ('pg_catalog.pg_attrdef'::pg_catalog.regclass,
                                'pg_catalog.pg_statistic_ext'::pg_catalog.regclass)
               OR (d.classid = 'pg_catalog.pg_rewrite'::pg_catalog.regclass
                   AND EXISTS (SELECT 1
                               FROM pg_catalog.pg_rewrite r
                               JOIN pg_catalog.pg_class c ON c.oid = r.ev_class
                               WHERE r.oid = d.objid AND c.relkind = 'm')))
    LOOP
        RAISE WARNING 'pg_pii_vault: % stores or indexes decrypted plaintext; drop it (and re-create it without decrypting) to restore crypto-shredding guarantees',
            dep.what;
    END LOOP;
END
$$;

-- Report indexes and stored generated columns built on the other functions
-- that 0.0.x declared IMMUTABLE: they keep working, but a dump of them can
-- no longer be restored, and piitext_in_text() stores plaintext.
DO $$
DECLARE
    dep record;
BEGIN
    FOR dep IN
        SELECT DISTINCT pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid) AS what,
               d.refobjid::pg_catalog.regprocedure AS func
        FROM pg_catalog.pg_depend d
        WHERE d.refclassid = 'pg_catalog.pg_proc'::pg_catalog.regclass
          AND d.refobjid IN ('piitext_encrypt(text, bytea)'::pg_catalog.regprocedure,
                             'piitext_encrypt_piitext(piitext, bytea)'::pg_catalog.regprocedure,
                             'piitext_in_text(text)'::pg_catalog.regprocedure)
          AND d.deptype IN ('n', 'a')
          AND ((d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                AND d.objsubid = 0
                AND EXISTS (SELECT 1 FROM pg_catalog.pg_class c
                            WHERE c.oid = d.objid AND c.relkind IN ('i', 'I')))
               OR (d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                   AND d.objsubid > 0
                   AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
                               WHERE a.attrelid = d.objid AND a.attnum = d.objsubid
                                 AND a.attgenerated <> ''))
               OR (d.classid = 'pg_catalog.pg_attrdef'::pg_catalog.regclass
                   AND EXISTS (SELECT 1
                               FROM pg_catalog.pg_attrdef ad
                               JOIN pg_catalog.pg_attribute a
                                 ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum
                               WHERE ad.oid = d.objid AND a.attgenerated <> '')))
    LOOP
        RAISE WARNING 'pg_pii_vault: % uses %, which is no longer IMMUTABLE: a dump of it cannot be restored; replace it with an ordinary column filled by the application or a trigger',
            dep.what, dep.func;
    END LOOP;
END
$$;

-- Function markings.
ALTER FUNCTION piitext_in_text(text) STABLE PARALLEL SAFE;
ALTER FUNCTION piitext_out_text(piitext) STABLE PARALLEL SAFE COST 100;
ALTER FUNCTION piitext_encrypt(text, bytea) VOLATILE CALLED ON NULL INPUT COST 100;
ALTER FUNCTION piitext_encrypt_piitext(piitext, bytea) VOLATILE CALLED ON NULL INPUT COST 100;
ALTER FUNCTION piitext_debug(piitext) IMMUTABLE PARALLEL SAFE;
ALTER FUNCTION piitext_raw(piitext) IMMUTABLE PARALLEL SAFE;

-- Casts: no text -> piitext at all, explicit piitext -> text/varchar.
DROP CAST (text AS piitext);
DROP CAST (piitext AS text);
CREATE CAST (piitext AS text) WITH FUNCTION piitext_out_text(piitext);
CREATE CAST (piitext AS varchar) WITH FUNCTION piitext_out_text(piitext);

-- Binary I/O.
CREATE FUNCTION "piitext_recv"(
	"internal" internal
) RETURNS PiiText
STABLE STRICT PARALLEL SAFE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_recv_wrapper';
CREATE FUNCTION "piitext_send"(
	"input" PiiText
) RETURNS bytea
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_send_wrapper';
ALTER TYPE piitext SET (RECEIVE = piitext_recv, SEND = piitext_send);
-- The input function depends on pii_vault.allow_staging.
ALTER FUNCTION piitext_in(cstring) STABLE;

-- New functions.
CREATE FUNCTION "piitext_reencrypt"(
	"input" PiiText
) RETURNS PiiText
STRICT VOLATILE COST 100
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_reencrypt_wrapper';
CREATE FUNCTION "piitext_is_encrypted"(
	"input" PiiText
) RETURNS bool
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_is_encrypted_wrapper';
CREATE FUNCTION "piitext_key_id"(
	"input" PiiText
) RETURNS bytea
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_key_id_wrapper';
CREATE FUNCTION "piitext_key_version"(
	"input" PiiText
) RETURNS bigint
IMMUTABLE STRICT PARALLEL SAFE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_key_version_wrapper';
CREATE FUNCTION "piitext_shred"(
	"key_id_bytes" bytea
) RETURNS bool
VOLATILE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_shred_wrapper';
-- OR REPLACE: development builds of 0.0.0 already shipped these two.
CREATE OR REPLACE FUNCTION "piitext_cache_evict"(
	"key_id_bytes" bytea
) RETURNS bool
STRICT VOLATILE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_cache_evict_wrapper';
CREATE OR REPLACE FUNCTION "piitext_cache_flush"() RETURNS bigint
STRICT VOLATILE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_cache_flush_wrapper';
CREATE FUNCTION "piitext_cache_invalidate"() RETURNS bool
STRICT VOLATILE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_cache_invalidate_wrapper';
CREATE FUNCTION "piitext_stats"() RETURNS TABLE (
	"metric" TEXT,
	"backend" bigint,
	"cluster" bigint
)
STRICT VOLATILE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_stats_wrapper';
CREATE FUNCTION "piitext_vault_check"() RETURNS TABLE (
	"check_name" TEXT,
	"ok" bool,
	"required" bool,
	"detail" TEXT
)
STRICT VOLATILE
LANGUAGE c
AS 'MODULE_PATHNAME', 'piitext_vault_check_wrapper';

-- Least privilege.
REVOKE ALL ON FUNCTION piitext_out_text(piitext) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_encrypt(text, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_encrypt_piitext(piitext, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_reencrypt(piitext) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_shred(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_cache_invalidate() FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_vault_check() FROM PUBLIC;
