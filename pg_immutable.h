/*
 * pg_immutable.h
 *   Common types, constants, and declarations for the pg_immutable extension.
 *
 * pg_immutable provides cryptographically verifiable immutability for
 * PostgreSQL records, resistant to SUPERUSER-level compromise.
 *
 * Copyright (c) 2026 MAlnahdi
 * MIT License
 */

#ifndef PG_IMMUTABLE_H
#define PG_IMMUTABLE_H

/* ---------------------------------------------------------------
 * Required PostgreSQL headers (included by the .c file)
 * This header only defines the public API and shared constants.
 * --------------------------------------------------------------- */

/* Extension name and version */
#define PG_IMMUTABLE_EXTNAME  "pg_immutable"
#define PG_IMMUTABLE_VERSION  "1.0"

/* Schema where internal metadata lives */
#define PG_IMMUTABLE_SCHEMA   "immutable"
#define PG_IMMUTABLE_SCHEMA_C "immutable"   /* C-string variant */

/* Internal table names */
#define CHAIN_TABLE_NAME      "hash_chain"
#define REGISTRY_TABLE_NAME   "table_registry"
#define CHECKPOINT_TABLE_NAME "checkpoints"
#define CHAIN_TABLE_FQN       "immutable.hash_chain"
#define REGISTRY_TABLE_FQN    "immutable.table_registry"
#define CHECKPOINT_TABLE_FQN  "immutable.checkpoints"
#define TRIGGER_FN_NAME       "immutable_chain_trigger_fn"
#define TRIGGER_NAME          "immutable_hash_trigger"

/*
 * Maximum column definitions for pg_immutable_create_immutable_table().
 * Adjust as needed.
 */
#define PG_IMMUTABLE_MAX_COLUMNS 1024

/*
 * Return codes for verification functions.
 */
typedef enum PgImmuVerifyResult
{
	PG_IMMU_VERIFY_OK               = 0,
	PG_IMMU_VERIFY_CHAIN_BROKEN     = 1,
	PG_IMMU_VERIFY_CHECKPOINT_INVALID = 2,
	PG_IMMU_VERIFY_TABLE_NOT_FOUND  = 3,
	PG_IMMU_VERIFY_INTERNAL_ERROR   = 4
} PgImmuVerifyResult;

/* Signature schemes */
#define PG_IMMU_SIGN_ALGORITHM "RSA-PKCS1v1.5-SHA256"
#define PG_IMMU_SIGN_PADDING   "PKCS1_PADDING"
#define PG_IMMU_SIGN_DIGEST    "SHA256"
#define PG_IMMU_CHECKPOINT_FORMAT_VERSION 1

/* OpenSSL RSA signing / verification (declared in pg_immutable.c) */
extern Datum pgimmutable_rsa_sign(PG_FUNCTION_ARGS);
extern Datum pgimmutable_rsa_verify(PG_FUNCTION_ARGS);
extern Datum pgimmutable_rsa_pubkey_fingerprint(PG_FUNCTION_ARGS);

#endif /* PG_IMMUTABLE_H */
