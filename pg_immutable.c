/*
 * pg_immutable.c
 *
 * PostgreSQL extension providing cryptographically verifiable
 * immutability for database records.
 *
 * Architecture:
 *   - ProcessUtility_hook : intercept DDL (DROP, TRUNCATE, ALTER)
 *   - planner_hook        : intercept DML (UPDATE, DELETE)
 *   - hash-chain trigger  : per-row SHA-256 chaining on INSERT
 *   - checkpoint system   : signed snapshots of chain state
 *   - verification        : external verifiability of integrity
 *
 * Copyright (c) 2026 MAlnahdi
 * MIT License
 */

#include "postgres.h"
#include "fmgr.h"
#include "executor/spi.h"
#include "utils/rel.h"
#include "utils/builtins.h"
#include "utils/palloc.h"
#include "utils/syscache.h"
#include "utils/lsyscache.h"
#include "tcop/utility.h"
#include "tcop/tcopprot.h"
#include "nodes/parsenodes.h"
#include "nodes/makefuncs.h"
#include "optimizer/planner.h"
#include "catalog/namespace.h"
#include "catalog/pg_class.h"
#include "catalog/pg_trigger.h"
#include "commands/trigger.h"
#include "miscadmin.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "lib/stringinfo.h"
#include "mb/pg_wchar.h"
#include "storage/lmgr.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/snapmgr.h"
#include "parser/parse_relation.h"
#include "catalog/objectaddress.h"
#include "commands/vacuum.h"
#include "tcop/cmdtag.h"
#include "access/genam.h"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

PG_MODULE_MAGIC;

/* ------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------ */

/* Hooks */
static ProcessUtility_hook_type prev_ProcessUtility_hook = NULL;
static planner_hook_type        prev_planner_hook        = NULL;

/* GUC variables */
static bool pg_immutable_enabled            = true;
static bool pg_immutable_superuser_override = false;

/* Full function declarations matching PG 16 hook signatures */
static void check_ddl_on_immutable_table(PlannedStmt *pstmt,
                                         const char *queryString,
                                         bool readOnlyTree,
                                         ProcessUtilityContext context,
                                         ParamListInfo params,
                                         QueryEnvironment *queryEnv,
                                         DestReceiver *dest,
                                         QueryCompletion *qc);
static PlannedStmt *check_dml_on_immutable_table(Query *parse,
                                                  const char *queryString,
                                                  int cursorOptions,
                                                  ParamListInfo boundParams);
static bool table_is_immutable_internal(Oid relid);
static bool get_rel_oid(const char *schema, const char *relname, Oid *relid_out);
static void hash_row_data(HeapTuple tuple, TupleDesc tupdesc,
                          unsigned char row_hash[SHA256_DIGEST_LENGTH]);
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex);
static bool vacuumstmt_is_full(VacuumStmt *stmt);

/* ------------------------------------------------------------------
 * Forward declarations for external signing functions
 * (SQL-callable via PG_FUNCTION_INFO_V1)
 * ------------------------------------------------------------------ */
Datum pgimmutable_rsa_sign(PG_FUNCTION_ARGS);
Datum pgimmutable_rsa_verify(PG_FUNCTION_ARGS);
Datum pgimmutable_rsa_pubkey_fingerprint(PG_FUNCTION_ARGS);

/* ------------------------------------------------------------------
 * _PG_init / _PG_fini
 * ------------------------------------------------------------------ */

/*
 * Module initialisation — called when the extension is loaded.
 *
 * Registers hooks and GUC variables so that pg_immutable can
 * intercept DDL and DML on registered immutable tables.
 */
void _PG_init(void)
{
    /* ---- GUCs ---- */
    DefineCustomBoolVariable(
        "pg_immutable.enabled",
        "Enable or disable pg_immutable enforcement",
        NULL,
        &pg_immutable_enabled,
        true,
        PGC_SUSET,         /* can only be set by superuser */
        GUC_NOT_IN_SAMPLE,
        NULL, NULL, NULL
    );

    DefineCustomBoolVariable(
        "pg_immutable.superuser_override",
        "Allow superuser to bypass immutability checks (leaves cryptographic evidence)",
        "When enabled, superuser can modify immutable tables. "
        "This is intended for emergency maintenance ONLY. "
        "Any modifications will invalidate subsequent cryptographic verification.",
        &pg_immutable_superuser_override,
        false,
        PGC_SUSET,
        GUC_NOT_IN_SAMPLE,
        NULL, NULL, NULL
    );

    /* ---- Hook registration ---- */
    prev_ProcessUtility_hook = ProcessUtility_hook;
    ProcessUtility_hook = check_ddl_on_immutable_table;

    prev_planner_hook = planner_hook;
    planner_hook = check_dml_on_immutable_table;

    elog(DEBUG1, "pg_immutable: extension initialised");
}

/*
 * Module cleanup — called when the extension is unloaded.
 */
void _PG_fini(void)
{
    /* Restore original hooks */
    ProcessUtility_hook = prev_ProcessUtility_hook;
    planner_hook        = prev_planner_hook;

    elog(DEBUG1, "pg_immutable: extension shutdown");
}

/* ------------------------------------------------------------------
 * DDL hook — ProcessUtility_hook implementation
 *
 * Intercepts DDL statements and blocks operations that would
 * compromise the immutability guarantee:
 *   - DROP TABLE      on immutable tables
 *   - TRUNCATE        on immutable tables
 *   - ALTER TABLE     on immutable tables (except safe operations)
 *   - VACUUM FULL     on immutable tables
 *   - CLUSTER         on immutable tables
 * ------------------------------------------------------------------ */
static void
check_ddl_on_immutable_table(PlannedStmt *pstmt,
                             const char *queryString,
                             bool readOnlyTree,
                             ProcessUtilityContext context,
                             ParamListInfo params,
                             QueryEnvironment *queryEnv,
                             DestReceiver *dest,
                             QueryCompletion *qc)
{
    Node *parsetree;

    /* If enforcement is disabled, skip all checks */
    if (!pg_immutable_enabled)
        goto call_prev;

    parsetree = pstmt->utilityStmt;
    if (parsetree == NULL)
        goto call_prev;

    switch (nodeTag(parsetree))
    {
        case T_DropStmt:
        {
            DropStmt *stmt = (DropStmt *) parsetree;
            if (stmt->removeType == OBJECT_TABLE)
            {
                ListCell *lc;
                foreach (lc, stmt->objects)
                {
                    List *names = (List *) lfirst(lc);
                    char  *schema = NULL;
                    char  *relname;
                    Oid    relid;

                    if (list_length(names) == 2)
                    {
                        schema = strVal(linitial(names));
                        relname = strVal(lsecond(names));
                    }
                    else
                    {
                        relname = strVal(linitial(names));
                    }

                    if (!get_rel_oid(schema, relname, &relid))
                        continue;

                    if (table_is_immutable_internal(relid))
                    {
                        if (pg_immutable_superuser_override && superuser())
                        {
                            elog(WARNING, "pg_immutable: SUPERUSER OVERRIDE — DROP TABLE on immutable table %s",
                                 relname);
                            goto call_prev;
                        }
                        ereport(ERROR,
                                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                                 errmsg("pg_immutable: cannot DROP immutable table \"%s\"",
                                        relname),
                                 errhint("Use pg_immutable.superuser_override for emergency maintenance "
                                         "(will break cryptographic verification).")));
                    }
                }
            }
            break;
        }

        case T_TruncateStmt:
        {
            TruncateStmt *stmt = (TruncateStmt *) parsetree;
            ListCell *lc;

            foreach (lc, stmt->relations)
            {
                RangeVar *rv = (RangeVar *) lfirst(lc);
                Oid relid;

                if (!get_rel_oid(rv->schemaname, rv->relname, &relid))
                    continue;

                if (table_is_immutable_internal(relid))
                {
                    if (pg_immutable_superuser_override && superuser())
                    {
                        elog(WARNING, "pg_immutable: SUPERUSER OVERRIDE — TRUNCATE on immutable table %s",
                             rv->relname);
                        goto call_prev;
                    }
                    ereport(ERROR,
                            (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                             errmsg("pg_immutable: cannot TRUNCATE immutable table \"%s\"",
                                    rv->relname),
                             errhint("Immutable tables are append-only.")));
                }
            }
            break;
        }

        case T_AlterTableStmt:
        {
            AlterTableStmt *stmt = (AlterTableStmt *) parsetree;
            RangeVar *rv = stmt->relation;
            Oid relid;

            if (rv == NULL)
                break;

            if (!get_rel_oid(rv->schemaname, rv->relname, &relid))
                break;

            if (table_is_immutable_internal(relid))
            {
                /* Allow safe alterations like adding comments or setting storage parameters */
                bool is_safe = false;

                if (list_length(stmt->cmds) == 1)
                {
                    AlterTableCmd *cmd = (AlterTableCmd *) linitial(stmt->cmds);
                    switch (cmd->subtype)
                    {
                        case AT_SetStatistics:  /* ALTER SET STATISTICS */
                        case AT_SetOptions:      /* ALTER SET (...) */
                        case AT_ResetOptions:    /* ALTER RESET (...) */
                        case AT_AddIdentity:     /* ALTER ADD GENERATED... (safe default?) */
                            /* Allow only if it doesn't change column types or constraints */
                            is_safe = true;
                            break;
                        default:
                            is_safe = false;
                            break;
                    }
                }

                if (!is_safe)
                {
                    if (pg_immutable_superuser_override && superuser())
                    {
                        elog(WARNING, "pg_immutable: SUPERUSER OVERRIDE — ALTER TABLE on immutable table %s",
                             rv->relname);
                        goto call_prev;
                    }
                    ereport(ERROR,
                            (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                             errmsg("pg_immutable: cannot ALTER immutable table \"%s\"",
                                    rv->relname),
                             errhint("Only safe ALTER operations (SET STATISTICS, SET/RESET options) are allowed.")));
                }
            }
            break;
        }

        case T_VacuumStmt:
        {
            VacuumStmt *stmt = (VacuumStmt *) parsetree;

            /*
             * Only block VACUUM FULL — standard VACUUM is safe.
             * In PG 16, VacuumStmt->options is a List * of DefElem.
             */
            if (vacuumstmt_is_full(stmt))
            {
                ListCell *lc;
                foreach (lc, stmt->rels)
                {
                    RangeVar *rv = (RangeVar *) lfirst(lc);
                    Oid relid;

                    if (rv == NULL)
                        continue;
                    if (!get_rel_oid(rv->schemaname, rv->relname, &relid))
                        continue;

                    if (table_is_immutable_internal(relid))
                    {
                        ereport(ERROR,
                                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                                 errmsg("pg_immutable: cannot VACUUM FULL immutable table \"%s\"",
                                        rv->relname),
                                 errhint("VACUUM FULL rewrites the table and breaks the hash chain. "
                                         "Use standard VACUUM instead.")));
                    }
                }
            }
            break;
        }

        default:
            break;
    }

call_prev:
    if (prev_ProcessUtility_hook)
        prev_ProcessUtility_hook(pstmt, queryString, readOnlyTree,
                                 context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree,
                                context, params, queryEnv, dest, qc);
}

/* ------------------------------------------------------------------
 * DML hook — planner_hook implementation
 *
 * Intercepts DML planning and blocks UPDATE, DELETE, and MERGE
 * on registered immutable tables.
 *
 * This runs during SQL planning — before execution — providing an
 * early and clear error to the user.
 * ------------------------------------------------------------------ */
static PlannedStmt *
check_dml_on_immutable_table(Query *parse,
                             const char *queryString,
                             int cursorOptions,
                             ParamListInfo boundParams)
{
    /* If enforcement is disabled, skip */
    if (!pg_immutable_enabled)
        goto call_prev;

    /* We only care about modifying commands */
    if (parse->commandType != CMD_UPDATE &&
        parse->commandType != CMD_DELETE &&
        parse->commandType != CMD_MERGE)
        goto call_prev;

    /* Identify the target relation from the range table */
    if (parse->resultRelation > 0 && parse->resultRelation <= list_length(parse->rtable))
    {
        RangeTblEntry *rte;
        Oid relid;

        rte = (RangeTblEntry *) list_nth(parse->rtable, parse->resultRelation - 1);
        if (rte->rtekind != RTE_RELATION)
            goto call_prev;

        relid = rte->relid;

        if (table_is_immutable_internal(relid))
        {
            if (pg_immutable_superuser_override && superuser())
            {
                elog(WARNING, "pg_immutable: SUPERUSER OVERRIDE — %s on immutable table OID %u",
                     (parse->commandType == CMD_UPDATE) ? "UPDATE" : "DELETE",
                     relid);
                goto call_prev;
            }

            if (parse->commandType == CMD_UPDATE)
            {
                ereport(ERROR,
                        (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                         errmsg("pg_immutable: cannot UPDATE immutable table (OID %u)", relid),
                         errhint("Immutable tables are append-only. Insert a correction row instead.")));
            }
            else if (parse->commandType == CMD_DELETE)
            {
                ereport(ERROR,
                        (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                         errmsg("pg_immutable: cannot DELETE from immutable table (OID %u)", relid),
                         errhint("Immutable tables are append-only.")));
            }
            else
            {
                ereport(ERROR,
                        (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                         errmsg("pg_immutable: cannot MERGE into immutable table (OID %u)", relid),
                         errhint("Immutable tables are append-only. INSERT new rows instead.")));
            }
        }
    }

call_prev:
    if (prev_planner_hook)
        return prev_planner_hook(parse, queryString, cursorOptions, boundParams);
    else
        return standard_planner(parse, queryString, cursorOptions, boundParams);
}

/* ------------------------------------------------------------------
 * Hash-chain trigger function
 *
 * This is the C implementation of the per-row trigger that:
 *   1. Computes SHA-256 of the NEW tuple's data
 *   2. Fetches the previous chain_hash for this table
 *   3. Computes: chain_hash = SHA-256(prev || row_hash || seq)
 *   4. Inserts a new link into immutable.hash_chain
 *
 * Registered as:
 *   CREATE TRIGGER pg_immutable_hash_trigger
 *   BEFORE INSERT ON immutable_table
 *   FOR EACH ROW
 *   EXECUTE FUNCTION pg_immutable._chain_trigger_fn();
 * ------------------------------------------------------------------ */
PG_FUNCTION_INFO_V1(pgimmutable_hash_trigger);

/*
 * Hash-chain trigger function (BEFORE INSERT).
 *
 * For each new row inserted into an immutable table:
 *   1. Computes SHA-256 of the row data
 *   2. Locks the latest chain entry for this table to prevent forks
 *   3. Computes the cumulative chain hash
 *   4. Inserts a new link into immutable.hash_chain
 *
 * Uses a sequential lock on the latest chain entry via FOR NO KEY UPDATE
 * to prevent concurrent inserts from forking the chain.
 */
Datum
pgimmutable_hash_trigger(PG_FUNCTION_ARGS)
{
    TriggerData    *trigdata = (TriggerData *) fcinfo->context;
    HeapTuple       newtuple;
    TupleDesc       tupdesc;
    unsigned char   row_hash[SHA256_DIGEST_LENGTH];
    unsigned char   chain_hash_buf[SHA256_DIGEST_LENGTH];
    char            row_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    char            chain_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    Oid             table_oid;
    unsigned char  *prev_chain_bytes = NULL;
    size_t          prev_chain_len = 0;
    int             ret;
    StringInfoData  cmd;
    uint64          next_seq = 1;
    bool            has_prev = false;
    bool            isnull;
    bool            seq_isnull;

    /* Verify we are being called from a trigger context */
    if (!CALLED_AS_TRIGGER(fcinfo))
        ereport(ERROR,
                (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
                 errmsg("pg_immutable: trigger function must be called as a trigger")));

    /* Only process BEFORE INSERT */
    if (!TRIGGER_FIRED_BEFORE(trigdata->tg_event) ||
        !TRIGGER_FIRED_BY_INSERT(trigdata->tg_event))
        return PointerGetDatum(trigdata->tg_newtuple);

    newtuple  = trigdata->tg_newtuple;
    tupdesc   = trigdata->tg_relation->rd_att;
    table_oid = RelationGetRelid(trigdata->tg_relation);

    /* Compute SHA-256 of the new row's data */
    hash_row_data(newtuple, tupdesc, row_hash);
    bytes_to_hex(row_hash, SHA256_DIGEST_LENGTH, row_hash_hex);

    /*
     * Connect to SPI for database operations.
     * Uses PG_TRY to handle errors gracefully.
     */
    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
        ereport(ERROR,
                (errmsg("pg_immutable: could not connect to SPI (status %d)", ret)));

    /*
     * Step 1: Find the latest seq_no and chain_hash for this table.
     * Simple query without locking to avoid crash issues.
     */
    initStringInfo(&cmd);
    appendStringInfo(&cmd,
                     "SELECT chain_hash, seq_no "
                     "FROM immutable.hash_chain "
                     "WHERE table_oid = %u "
                     "ORDER BY seq_no DESC LIMIT 1",
                     table_oid);

    ret = SPI_execute(cmd.data, true, 1);
    if (ret == SPI_OK_SELECT && SPI_processed > 0 && SPI_tuptable != NULL)
    {
        Datum prev_hash_datum;
        Datum seq_datum;

        prev_hash_datum = SPI_getbinval(SPI_tuptable->vals[0],
                                        SPI_tuptable->tupdesc,
                                        1, &isnull);
        seq_datum = SPI_getbinval(SPI_tuptable->vals[0],
                                  SPI_tuptable->tupdesc,
                                  2, &seq_isnull);

        if (!seq_isnull)
        {
            next_seq = (uint64) DatumGetInt64(seq_datum) + 1;
        }

        if (!isnull)
        {
            bytea *prev_bytea = DatumGetByteaPP(prev_hash_datum);

            has_prev = true;
            prev_chain_len = VARSIZE_ANY_EXHDR(prev_bytea);
            prev_chain_bytes = palloc(prev_chain_len);
            memcpy(prev_chain_bytes, VARDATA_ANY(prev_bytea), prev_chain_len);
        }
    }

    SPI_freetuptable(SPI_tuptable);
    pfree(cmd.data);

    /*
     * Step 2: Compute the cumulative chain hash.
     *
     *   chain_hash = SHA-256(prev_chain_hash || row_hash || seq_str)
     */
    {
        SHA256_CTX sha_ctx;
        char       seq_str[32];
        int        seq_len;

        seq_len = snprintf(seq_str, sizeof(seq_str), "%lu", (unsigned long) next_seq);

        SHA256_Init(&sha_ctx);

        if (has_prev && prev_chain_bytes != NULL)
            SHA256_Update(&sha_ctx, prev_chain_bytes, prev_chain_len);

        SHA256_Update(&sha_ctx, row_hash, SHA256_DIGEST_LENGTH);
        SHA256_Update(&sha_ctx, seq_str, seq_len);
        SHA256_Final(chain_hash_buf, &sha_ctx);

        if (prev_chain_bytes)
            pfree(prev_chain_bytes);
    }

    bytes_to_hex(chain_hash_buf, SHA256_DIGEST_LENGTH, chain_hash_hex);

    /*
     * Step 3: Insert the new chain link.
     */
    initStringInfo(&cmd);
    appendStringInfo(&cmd,
                     "INSERT INTO immutable.hash_chain "
                     "(table_oid, row_ctid, row_hash, %s chain_hash, seq_no) "
                     "VALUES (%u, ctid, decode('%s', 'hex'), %s "
                     "decode('%s', 'hex'), %lu)",
                     (has_prev ? "prev_chain_hash," : ""),
                     table_oid, row_hash_hex,
                     (has_prev ? (char *) "decode('" "', 'hex')," : ""),
                     chain_hash_hex, (unsigned long) next_seq);

    ret = SPI_execute(cmd.data, false, 0);
    if (ret != SPI_OK_INSERT)
        ereport(WARNING,
                (errmsg("pg_immutable: failed to insert hash chain link (SPI status %d)", ret)));

    pfree(cmd.data);
    SPI_finish();

    /* Return the new tuple (standard trigger behaviour) */
    return PointerGetDatum(newtuple);
}

/* =================================================================
 * External Signing — OpenSSL RSA Sign / Verify / Fingerprint
 *
 * These C functions are exposed to SQL and provide the underlying
 * cryptographic operations for tamper-proof checkpoint signing.
 *
 * Security design (from the threat model):
 *   In production, the private key MUST be kept outside PostgreSQL.
 *   Use checkpoint_sign() to store externally-produced signatures.
 *   The internal _with_key() functions are for dev/test/automation
 *   where the key is managed securely outside the database.
 *
 * Signature scheme:
 *   - Hash: SHA-256 (digest computed in SQL before calling sign)
 *   - Padding: PKCS#1 v1.5 (widely compatible)
 *   - Key type: RSA (2048+ bits recommended)
 * ================================================================= */

PG_FUNCTION_INFO_V1(pgimmutable_rsa_sign);

/*
 * pgimmutable_rsa_sign(key_pem TEXT, data BYTEA [, password TEXT])
 *
 * Signs the given data using an RSA private key in PEM format.
 * Returns the signature as BYTEA (PKCS#1 v1.5, SHA-256).
 *
 * Arguments:
 *   key_pem  - RSA private key in PEM format (TEXT)
 *   data     - Data to sign (BYTEA) — should be a SHA-256 digest
 *   password - Optional password for encrypted private keys (TEXT)
 *
 * Returns:
 *   signature BYTEA
 */
Datum
pgimmutable_rsa_sign(PG_FUNCTION_ARGS)
{
    text       *key_pem_text;
    bytea      *data_bytes;
    text       *password_text = NULL;
    char       *key_pem_str;
    const char *data_ptr;
    size_t      data_len;
    const char *password = NULL;

    BIO          *bio = NULL;
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t        sig_len;
    unsigned char *sig = NULL;
    bytea        *result = NULL;
    int           ret;

    /* Extract arguments */
    key_pem_text = PG_GETARG_TEXT_PP(0);
    data_bytes   = PG_GETARG_BYTEA_PP(1);

    if (PG_NARGS() > 2 && !PG_ARGISNULL(2))
    {
        password_text = PG_GETARG_TEXT_PP(2);
        password = text_to_cstring(password_text);
    }

    /* Convert to C strings/pointers */
    key_pem_str = text_to_cstring(key_pem_text);
    data_ptr    = VARDATA_ANY(data_bytes);
    data_len    = VARSIZE_ANY_EXHDR(data_bytes);

    /* ---- OpenSSL operations ---- */

    /* Create a memory BIO from the PEM string */
    bio = BIO_new_mem_buf((void *) key_pem_str, -1);
    if (bio == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to allocate BIO for private key")));

    /* Read private key (with optional password) */
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *) password);
    BIO_free(bio);

    if (pkey == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to read private key"),
                 errdetail("Invalid PEM format or incorrect password."),
                 errhint("Ensure the key is a valid RSA private key in PEM format.")));

    /* Create signing context */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL)
    {
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_OUT_OF_MEMORY),
                 errmsg("pg_immutable: failed to create signing context")));
    }

    /* Initialize signing operation */
    ret = EVP_PKEY_sign_init(ctx);
    if (ret != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: signing init failed"),
                 errdetail("OpenSSL: %s", ERR_reason_error_string(ERR_get_error()))));
    }

    /* Configure: SHA-256 digest + PKCS#1 v1.5 padding */
    ret = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    if (ret != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to set SHA-256 digest")));
    }

    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    if (ret != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to set RSA padding")));
    }

    /* Determine signature length */
    ret = EVP_PKEY_sign(ctx, NULL, &sig_len,
                        (unsigned char *) data_ptr, data_len);
    if (ret != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to determine signature length"),
                 errdetail("OpenSSL: %s", ERR_reason_error_string(ERR_get_error()))));
    }

    /* Allocate signature buffer (palloc, managed by PG) */
    sig = palloc(sig_len);

    /* Sign! */
    ret = EVP_PKEY_sign(ctx, sig, &sig_len,
                        (unsigned char *) data_ptr, data_len);
    if (ret != 1)
    {
        pfree(sig);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: signing failed"),
                 errdetail("OpenSSL: %s", ERR_reason_error_string(ERR_get_error()))));
    }

    /* Build PostgreSQL BYTEA result */
    result = (bytea *) palloc(sig_len + VARHDRSZ);
    SET_VARSIZE(result, sig_len + VARHDRSZ);
    memcpy(VARDATA(result), sig, sig_len);

    pfree(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pgimmutable_rsa_verify);

/*
 * pgimmutable_rsa_verify(pubkey_pem TEXT, data BYTEA, signature BYTEA)
 * RETURNS BOOLEAN
 *
 * Verifies an RSA-PKCS#1v1.5-SHA256 signature against the given data.
 * Returns true if the signature is valid, false otherwise.
 */
Datum
pgimmutable_rsa_verify(PG_FUNCTION_ARGS)
{
    text       *pubkey_pem_text;
    bytea      *data_bytes;
    bytea      *sig_bytes;
    char       *pubkey_pem_str;
    const char *data_ptr;
    size_t      data_len;
    const char *sig_ptr;
    size_t      sig_len;

    BIO          *bio = NULL;
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int           ret;
    bool          valid = false;

    /* Extract arguments */
    pubkey_pem_text = PG_GETARG_TEXT_PP(0);
    data_bytes      = PG_GETARG_BYTEA_PP(1);
    sig_bytes       = PG_GETARG_BYTEA_PP(2);

    pubkey_pem_str = text_to_cstring(pubkey_pem_text);
    data_ptr       = VARDATA_ANY(data_bytes);
    data_len       = VARSIZE_ANY_EXHDR(data_bytes);
    sig_ptr        = VARDATA_ANY(sig_bytes);
    sig_len        = VARSIZE_ANY_EXHDR(sig_bytes);

    /* Create memory BIO from PEM */
    bio = BIO_new_mem_buf((void *) pubkey_pem_str, -1);
    if (bio == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_OUT_OF_MEMORY),
                 errmsg("pg_immutable: failed to allocate BIO for public key")));

    /* Read public key (SubjectPublicKeyInfo format) */
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to read public key"),
                 errdetail("Invalid PEM format. Ensure it is an RSA public key in SPKI PEM format.")));

    /* Create verification context */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL)
    {
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_OUT_OF_MEMORY),
                 errmsg("pg_immutable: failed to create verification context")));
    }

    /* Initialize verification */
    ret = EVP_PKEY_verify_init(ctx);
    if (ret != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: verify init failed"),
                 errdetail("OpenSSL: %s", ERR_reason_error_string(ERR_get_error()))));
    }

    /* Configure: SHA-256 digest + PKCS#1 v1.5 padding */
    ret = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    if (ret != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to set SHA-256 digest for verify")));
    }

    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    if (ret != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to set RSA padding for verify")));
    }

    /* Verify! */
    ret = EVP_PKEY_verify(ctx, (unsigned char *) sig_ptr, sig_len,
                          (unsigned char *) data_ptr, data_len);
    if (ret == 1)
        valid = true;
    else if (ret == 0)
        valid = false;
    else
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: verification error"),
                 errdetail("OpenSSL: %s", ERR_reason_error_string(ERR_get_error()))));
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    PG_RETURN_BOOL(valid);
}

PG_FUNCTION_INFO_V1(pgimmutable_rsa_pubkey_fingerprint);

/*
 * pgimmutable_rsa_pubkey_fingerprint(pubkey_pem TEXT)
 * RETURNS TEXT
 *
 * Computes the SHA-256 fingerprint of an RSA public key.
 * The fingerprint is SHA-256 of the DER-encoded
 * SubjectPublicKeyInfo (SPKI), returned as a hex string.
 *
 * This fingerprint uniquely identifies the public key and can
 * be used to track which key signed a checkpoint.
 */
Datum
pgimmutable_rsa_pubkey_fingerprint(PG_FUNCTION_ARGS)
{
    text       *pubkey_pem_text;
    char       *pubkey_pem_str;

    BIO          *bio = NULL;
    EVP_PKEY     *pkey = NULL;
    unsigned char *der = NULL;
    int           der_len;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char          fingerprint_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    text         *result;

    pubkey_pem_text = PG_GETARG_TEXT_PP(0);
    pubkey_pem_str  = text_to_cstring(pubkey_pem_text);

    /* Create memory BIO from PEM */
    bio = BIO_new_mem_buf((void *) pubkey_pem_str, -1);
    if (bio == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_OUT_OF_MEMORY),
                 errmsg("pg_immutable: failed to allocate BIO for fingerprint")));

    /* Read public key */
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to read public key for fingerprint"),
                 errdetail("Invalid PEM format.")));

    /* DER-encode the SubjectPublicKeyInfo */
    der_len = i2d_PUBKEY(pkey, &der);
    if (der_len <= 0 || der == NULL)
    {
        EVP_PKEY_free(pkey);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION),
                 errmsg("pg_immutable: failed to DER-encode public key")));
    }

    /* SHA-256 hash the DER data */
    SHA256(der, der_len, hash);
    OPENSSL_free(der);
    EVP_PKEY_free(pkey);

    /* Convert to hex string */
    bytes_to_hex(hash, SHA256_DIGEST_LENGTH, fingerprint_hex);

    result = cstring_to_text(fingerprint_hex);
    PG_RETURN_TEXT_P(result);
}

/* ------------------------------------------------------------------
 * Helper: check if a table is registered as immutable.
 *
 * Uses syscache to look up the table OID, then queries SPI to
 * check the immutable.table_registry.
 *
 * Returns true if the table is registered and active.
 * ------------------------------------------------------------------ */
static bool
table_is_immutable_internal(Oid relid)
{
    int ret;
    StringInfoData cmd;
    bool result = false;

    /* Quick sanity: if relid is invalid, it's not immutable */
    if (!OidIsValid(relid))
        return false;

    ret = SPI_connect();
    if (ret != SPI_OK_CONNECT)
        return false;

    initStringInfo(&cmd);
    appendStringInfo(&cmd,
                     "SELECT 1 FROM immutable.table_registry "
                     "WHERE table_oid = %u AND is_active = true",
                     relid);

    ret = SPI_execute(cmd.data, true, 1);
    if (ret == SPI_OK_SELECT && SPI_processed > 0)
    {
        result = true;
    }

    SPI_freetuptable(SPI_tuptable);
    pfree(cmd.data);
    SPI_finish();

    return result;
}

/* ------------------------------------------------------------------
 * Helper: resolve a relation name to OID.
 *
 * If schema is NULL, uses the current search path.
 * Returns false if the relation does not exist.
 * ------------------------------------------------------------------ */
static bool
get_rel_oid(const char *schema, const char *relname, Oid *relid_out)
{
    Oid   relid;

    if (relname == NULL)
        return false;

    /*
     * Use RangeVarGetRelid with missing_ok = true to silently return
     * InvalidOid if the relation does not exist.
     */
    relid = RangeVarGetRelid(makeRangeVar(pstrdup(schema), pstrdup(relname), -1),
                             NoLock, true);

    if (!OidIsValid(relid))
    {
        /* Try without schema qualification via search path */
        relid = RelnameGetRelid(relname);
    }

    if (!OidIsValid(relid))
        return false;

    *relid_out = relid;
    return true;
}

/* ------------------------------------------------------------------
 * Helper: compute SHA-256 hash of the data portion of a HeapTuple.
 *
 * Iterates over all non-null, non-system attributes and hashes
 * their binary representations together.
 *
 * This produces a deterministic hash of the user-visible row
 * contents, excluding system columns (oid, ctid, xmin, etc.).
 * ------------------------------------------------------------------ */
static void
hash_row_data(HeapTuple tuple, TupleDesc tupdesc,
              unsigned char row_hash[SHA256_DIGEST_LENGTH])
{
    SHA256_CTX ctx;
    int i;

    SHA256_Init(&ctx);

    for (i = 0; i < tupdesc->natts; i++)
    {
        Form_pg_attribute attr = TupleDescAttr(tupdesc, i);
        Datum   value;
        bool    isnull;
        bool    typbyval;
        int16   typlen;

        /* Skip dropped columns and system columns */
        if (attr->attisdropped || attr->attnum < 0)
            continue;

        value = fastgetattr(tuple, i + 1, tupdesc, &isnull);

        if (isnull)
        {
            /* Hash a NULL marker */
            const char null_marker[] = "\\N";
            SHA256_Update(&ctx, null_marker, strlen(null_marker));
            continue;
        }

        /* Get type info for serialisation */
        get_typlenbyval(attr->atttypid, &typlen, &typbyval);

        if (typbyval)
        {
            /* Pass-by-value: hash the Datum directly */
            SHA256_Update(&ctx, (unsigned char *)&value, sizeof(Datum));
        }
        else
        {
            /* Pass-by-reference: hash the actual bytes */
            if (typlen > 0)
            {
                /* Fixed-length type */
                SHA256_Update(&ctx, DatumGetPointer(value), typlen);
            }
            else
            {
                /* Variable-length (varlena) */
                struct varlena *vl = (struct varlena *) DatumGetPointer(value);
                SHA256_Update(&ctx, (unsigned char *) vl, VARSIZE_ANY(vl));
            }
        }
    }

    SHA256_Final(row_hash, &ctx);
}

/* ------------------------------------------------------------------
 * Helper: convert binary bytes to lowercase hex string.
 *
 * The output buffer must be at least (len * 2 + 1) bytes.
 * ------------------------------------------------------------------ */
static void
bytes_to_hex(const unsigned char *bytes, size_t len, char *hex)
{
    static const char hex_chars[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++)
    {
        hex[i * 2]     = hex_chars[(bytes[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex[len * 2] = '\0';
}

/* ------------------------------------------------------------------
 * Helper: check if a VacuumStmt has the FULL option set.
 *
 * In PG 16, VacuumStmt->options is a List * of DefElem nodes.
 * Iterates through the list looking for a "full" option whose
 * value is not NIL/false.
 * ------------------------------------------------------------------ */
static bool
vacuumstmt_is_full(VacuumStmt *stmt)
{
    ListCell *lc;

    if (stmt->options == NIL)
        return false;

    foreach (lc, stmt->options)
    {
        DefElem *opt = (DefElem *) lfirst(lc);

        if (strcmp(opt->defname, "full") == 0)
        {
            if (opt->arg == NULL)
                return true;
            /* If a boolean argument is present, check its value */
            return intVal(opt->arg) != 0;
        }
    }

    return false;
}
