# pg_immutable — Developer Documentation

> **Version:** 1.0  
> **License:** MIT  
> **Copyright:** © 2026 MAlnahdi

---

## Table of Contents

1. [Overview & Architecture](#1-overview--architecture)
2. [Project Structure](#2-project-structure)
3. [Building & Installing](#3-building--installing)
4. [Internal Schema](#4-internal-schema)
5. [Public API Reference](#5-public-api-reference)
6. [External Signing API](#6-external-signing-api)
7. [Other Functions](#7-other-functions)
8. [C Extension Internals](#8-c-extension-internals)
9. [SQL Extension Internals](#9-sql-extension-internals)
10. [Hash Chain Cryptography](#10-hash-chain-cryptography)
11. [Security Model](#11-security-model)
12. [Threat Model](#12-threat-model)
13. [Development Guide](#13-development-guide)
14. [Testing Guide](#14-testing-guide)
15. [Configuration Reference](#15-configuration-reference)
16. [Known Limitations](#16-known-limitations)

---

## 1. Overview & Architecture

`pg_immutable` provides **cryptographically verifiable immutability** for PostgreSQL records. It enforces append-only semantics at the SQL level while maintaining a cryptographic hash chain that enables tamper detection — even against PostgreSQL `SUPERUSER` compromise.

### System Layers

```
┌─────────────────────────────────────────────────────────┐
│                    Application / Client                   │
├─────────────────────────────────────────────────────────┤
│                   PostgreSQL Data Plane                   │
│  ┌───────────────────────────────────────────────────┐   │
│  │                  pg_immutable                      │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────┐ │   │
│  │  │ DDL Hook     │  │ DML Hook     │  │ Hash     │ │   │
│  │  │ (ProcessUtly)│  │ (Planner)    │  │ Chain    │ │   │
│  │  └─────────────┘  └──────────────┘  │ Trigger  │ │   │
│  │                                     └──────────┘ │   │
│  └───────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│              External Signing Authority                   │
│  ┌───────────────────────────────────────────────────┐   │
│  │  HSM / KMS / Isolated Signing Service             │   │
│  │  (Private Key NEVER exposed to PostgreSQL)        │   │
│  └───────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│               Cryptographic Trust Anchor                  │
│          (Independent Verification Possible)               │
└─────────────────────────────────────────────────────────┘
```

### Core Principle

> A compromised PostgreSQL instance must not be able to create a cryptographically valid representation of a modified historical state without access to an externally protected private signing key.

### Enforcement Layers

| Layer | Mechanism | What It Blocks |
|-------|-----------|----------------|
| **SQL DDL** | `ProcessUtility_hook` (C) | `DROP`, `TRUNCATE`, unsafe `ALTER`, `VACUUM FULL` |
| **SQL DML** | `planner_hook` (C) | `UPDATE`, `DELETE`, `MERGE` |
| **Row-level** | `BEFORE INSERT` trigger (PL/pgSQL) | Records hash chain links |
| **Cryptographic** | SHA-256 chain + checkpoints | Tamper evidence via verification |
| **External** | Signed checkpoint export | Independent offline audit |

---

## 2. Project Structure

```
pg_immutable/
├── Makefile                 # PGXS build configuration
├── pg_immutable.control     # PostgreSQL extension control file
├── pg_immutable.h           # Common constants, types, declarations
├── pg_immutable.c           # C source: hooks, trigger, helpers
├── pg_immutable--1.0.sql    # SQL definitions: schema, tables, functions
├── scripts/                 # Standalone utility scripts
│   └── verify_checkpoint.sh # External checkpoint signature verifier
├── pg_immutable_plan.md     # Architecture plan & threat model
├── README.md                # User-facing README
├── doc.md                   # Developer documentation (this file)
├── LICENSE                  # MIT License
└── .gitignore               # Build artifact exclusions
```

### File Responsibilities

| File | Purpose | Language |
|------|---------|----------|
| `pg_immutable.control` | Extension metadata: name, version, schema, module path | INI-like |
| `pg_immutable.h` | Shared C constants (schema names, table names, enum return codes) | C header |
| `pg_immutable.c` | Core C logic: `_PG_init`, hooks, hash chain trigger, SPIs | C |
| `pg_immutable--1.0.sql` | All SQL objects: schemas, tables, functions, triggers | SQL / PL/pgSQL |
| `Makefile` | PGXS build rules; compiles and installs the extension | Make |
| `scripts/verify_checkpoint.sh` | Standalone bash script; verifies checkpoint signatures via OpenSSL CLI — no PostgreSQL needed | Bash |

---

## 3. Building & Installing

### Prerequisites

```bash
# PostgreSQL server development headers (adjust version to match your PG)
sudo apt-get install postgresql-server-dev-<version>  # e.g., 16 for PG 16

# OpenSSL development headers (for SHA-256 in C code)
sudo apt-get install libssl-dev
```

### Build

```bash
cd /path/to/pg_immutable

# Using default pg_config (adjust path if multiple PG versions exist)
make

# Or specify PG version explicitly
make PG_CONFIG=/usr/lib/postgresql/16/bin/pg_config
```

### Install

```bash
# Requires root to copy files into PostgreSQL's extension directory
sudo make install

# Or with explicit PG_CONFIG
sudo make install PG_CONFIG=/usr/lib/postgresql/16/bin/pg_config
```

This installs three files:
- `pg_immutable.so` → `$PG_LIBDIR/` (shared library)
- `pg_immutable.control` → `$SHAREDIR/extension/` (control file)
- `pg_immutable--1.0.sql` → `$SHAREDIR/extension/` (SQL definitions)

### Enable in PostgreSQL

**Required for full protection (DDL/DML hooks):**

**Option A — Server-wide (recommended for production):**
Add to `postgresql.conf`:
```ini
shared_preload_libraries = 'pg_immutable'
```
Then restart PostgreSQL:
```bash
sudo systemctl restart postgresql
```

**Option B — Per-session (for development/testing only):**
```sql
LOAD 'pg_immutable';
```
This registers the hooks for the current backend session only and does not require a restart. Not suitable for production because each new connection must `LOAD` the library.

Then create the extension in your database:
```sql
CREATE EXTENSION pg_immutable;
```

> ⚠️ Without `shared_preload_libraries`, the C hooks that block `UPDATE`/`DELETE`/`DROP`/etc. will not be registered. Only the hash chain trigger and verification functions will work.

---

## 4. Internal Schema

All internal objects live in the `immutable` schema (auto-created by the extension).

### `immutable.table_registry`

Tracks which database tables are registered as immutable.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `SERIAL` | Auto-incrementing primary key |
| `table_schema` | `NAME` | Schema of the immutable table |
| `table_name` | `NAME` | Name of the immutable table |
| `table_oid` | `OID` | Object ID of the table (unique) |
| `created_at` | `TIMESTAMPTZ` | When the table was registered |
| `is_active` | `BOOLEAN` | Whether the registration is active |

Constraints: `UNIQUE (table_oid)`

### `immutable.hash_chain`

Cryptographic chain linking every row inserted into immutable tables.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `BIGSERIAL` | Auto-incrementing primary key |
| `table_oid` | `OID` | OID of the immutable table |
| `row_ctid` | `TID` | Physical location of the row (nullable; NULL for freshly inserted rows since CTID isn't assigned yet in BEFORE INSERT) |
| `row_hash` | `BYTEA` | SHA-256 hash of the row's JSON representation |
| `prev_chain_hash` | `BYTEA` | Chain hash of the predecessor link (NULL for first row) |
| `chain_hash` | `BYTEA` | Cumulative chain hash: `SHA-256(prev \|\| row_hash \|\| seq)` |
| `seq_no` | `BIGINT` | Monotonically increasing sequence number per table |
| `created_at` | `TIMESTAMPTZ` | When the chain link was created |

Index: `idx_hash_chain_table ON (table_oid, seq_no DESC)`

### `immutable.checkpoints`

Snapshots of hash chain state, optionally signed by an external authority.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `BIGSERIAL` | Auto-incrementing primary key |
| `checkpoint_data` | `JSONB` | Snapshot of chain heads, database info, timestamp |
| `signature` | `BYTEA` | External digital signature (e.g., from HSM/KMS) |
| `signed_at` | `TIMESTAMPTZ` | When the signature was stored |
| `is_finalized` | `BOOLEAN` | Whether this checkpoint is finalized (signed) |
| `created_at` | `TIMESTAMPTZ` | When the checkpoint was created |

---

## 5. Public API Reference

All public functions are in the `immutable` schema. Call them as `immutable.function_name()`.

### `immutable.create_immutable_table(schema TEXT, table_name TEXT, columns TEXT) → TEXT`

Creates a new table with the given column specification and immediately registers it as immutable.

**Parameters:**
- `schema` — Target schema (e.g., `'public'`)
- `table_name` — Table name (e.g., `'ledger'`)
- `columns` — Column definitions as a SQL string (same format as `CREATE TABLE`)

**Returns:** Status message with the new table's OID.

**Example:**
```sql
SELECT immutable.create_immutable_table('public', 'ledger',
  'id SERIAL PRIMARY KEY,
   account_id INT NOT NULL,
   amount NUMERIC(12,2) NOT NULL,
   description TEXT,
   created_at TIMESTAMPTZ DEFAULT now()'
);
```

### `immutable.make_immutable(schema TEXT, table_name TEXT) → TEXT`

Marks an *existing* table as immutable. Installs the hash chain trigger to protect future inserts. (Note: hashing of existing rows is a placeholder — currently returns a row count without inserting into the chain.)

**Parameters:**
- `schema` — Schema of the existing table
- `table_name` — Name of the existing table

**Returns:** Status message with the table's OID.

**CAUTION:** Existing rows cannot be retroactively protected against pre-immutability modifications, but their current hashes are captured.

### `immutable.verify(table_schema TEXT, table_name TEXT) → INTEGER`

Verifies the cryptographic hash chain for a single immutable table.

**Return codes:**
| Code | Constant | Meaning |
|------|----------|---------|
| `0` | `OK` | Chain is intact |
| `1` | `CHAIN_BROKEN` | Hash mismatch detected (tampering) |
| `3` | `TABLE_NOT_FOUND` | Table doesn't exist or is not registered |
| `4` | `INTERNAL_ERROR` | Unexpected error |

**Algorithm:** Walks the entire chain for the table in `seq_no` order, recomputes each link's expected `chain_hash`, and compares it to the stored value. Also verifies chain structure (first link has no predecessor, subsequent links reference previous).

### `immutable.verify_all() → TABLE(schema NAME, table_name NAME, status TEXT, message TEXT)`

Verifies all registered immutable tables and returns a summary as a table.

**Status values:** `'OK'`, `'CHAIN_BROKEN'`, `'TABLE_NOT_FOUND'`, `'ERROR'`, `'NO_TABLES'`

### `immutable.checkpoint_create() → JSONB`

Creates a checkpoint of the current hash-chain state for all active immutable tables.

**Checkpoint JSON structure:**
```json
{
  "format_version": 1,
  "database_id": "12345",
  "database_name": "mydb",
  "checkpoint_seq": 1,
  "created_at": "2026-07-27T12:00:00+00:00",
  "num_tables": 2,
  "table_heads": [
    {
      "schema": "public",
      "table": "ledger",
      "table_oid": "54321",
      "chain_head": "abc123..."
    }
  ]
}
```

### `immutable.checkpoint_sign(ckpt_id BIGINT, signature_hex TEXT) → BOOLEAN`

Stores an externally-provided digital signature for a checkpoint.

**Parameters:**
- `ckpt_id` — Checkpoint ID from `checkpoint_create()`
- `signature_hex` — Hex-encoded digital signature

**Usage flow:**
1. Create checkpoint → get ID
2. Compute digest to sign: `SELECT encode(sha256(checkpoint_data::text::bytea), 'hex') FROM immutable.checkpoints WHERE id = 1;`
3. Sign the digest using external HSM/KMS
4. Store signature: `SELECT immutable.checkpoint_sign(1, '<hex-signature>');`

### `immutable.export_checkpoint(ckpt_id BIGINT) → TEXT`

Exports a checkpoint as a human-readable text document suitable for independent offline verification.

**Export format:**
```
=== immutable Checkpoint Export ===
Checkpoint ID  : 1
Created At     : 2026-07-27 15:13:30.418761+03
Signed At      : (not signed)
Is Finalized   : f

--- Checkpoint Data ---
{"format_version": 1, ...}

--- SHA-256 Digest To Verify (hex) ---
e9212a2e16e5c02fbeca98b9a400f32e9beffcdb258d01385c81baee4f1e886d

=== End of Export ===
```

If signed, also includes:
```
--- Digital Signature (hex) ---
deadbeef...
```

### `immutable.export_checkpoint_for_verification(ckpt_id BIGINT [, pubkey_pem TEXT]) → TEXT`

Enhanced export that includes the signing key's SHA-256 fingerprint and ready-to-run OpenSSL CLI verification commands using `openssl pkeyutl`. If a public key is provided, it computes the key fingerprint and embeds the exact OpenSSL command line for independent verification.

---

## 6. External Signing API

`pg_immutable` provides both **internal signing** (RSA inside PostgreSQL) and **external signing** (sign via HSM/KMS, store the result) flows. The security architecture mandates that production systems use the external flow.

### Signature Scheme

| Parameter | Value |
|-----------|-------|
| Algorithm | RSA with PKCS#1 v1.5 padding |
| Hash | SHA-256 |
| Key size | 2048+ bits (recommended) |
| What is signed | SHA-256(`checkpoint_data::text::bytea`) |

### Production Flow (Recommended)

**Step 1** — Create a checkpoint:
```sql
SELECT immutable.checkpoint_create();
```

**Step 2** — Get the digest to sign:
```sql
SELECT encode(
  sha256(checkpoint_data::text::bytea), 'hex'
) AS digest_to_sign
FROM immutable.checkpoints WHERE id = 1;
```

**Step 3** — Sign the digest using an external HSM/KMS (key never touches the DB):
```bash
# Copy the hex digest from Step 2, then:
echo -n '<digest-hex>' | xxd -r -p > checkpoint_digest.bin
openssl pkeyutl -sign -inkey private.pem -in checkpoint_digest.bin -out checkpoint.sig -pkeyopt digest:sha256
xxd -p -c 256 checkpoint.sig  # get hex signature
```

**Step 4** — Store the signature back in PostgreSQL:
```sql
SELECT immutable.checkpoint_sign(1, '<hex-signature-from-step-3>');
```

### Development Flow (Internal Signing)

⚠️ **Only for development/testing.** The private key is passed to PostgreSQL.

**Step 1** — Generate a key pair (on a trusted machine):
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

**Step 2** — Create checkpoint and sign inside PostgreSQL:
```sql
SELECT immutable.checkpoint_create();
SELECT immutable.checkpoint_sign_with_key(1,
  pg_read_file('/path/to/private.pem')
);
```

**Step 3** — Verify using the public key:
```sql
SELECT immutable.verify_checkpoint_signature(1,
  pg_read_file('/path/to/public.pem')
);
```

### Standalone Verification

An external auditor can verify a checkpoint **without any database connection** using the standalone function:

```sql
SELECT immutable.verify_external_checkpoint(
  '{"format_version":1,"database_name":"test",...}',
  decode('abc123...', 'hex'),
  '-----BEGIN PUBLIC KEY-----\n...-----END PUBLIC KEY-----'
);
```

Or using the OpenSSL CLI (pkeyutl, because the digest is pre-hashed):
```bash
openssl pkeyutl -verify -pubin -inkey public.pem \
  -in checkpoint_digest.bin -sigfile checkpoint.sig \
  -pkeyopt digest:sha256
```

### Complete External Verification Example

The following is a complete end-to-end test proving that an external auditor can verify a checkpoint **without trusting PostgreSQL at all**:

```bash
# 1. Generate a key pair (on a trusted machine, never on the DB server)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 2. Extract the digest and signature from the database
psql -h localhost -U postgres -d mydb -t -A \
  -c "SELECT encode(sha256(checkpoint_data::text::bytea), 'hex')
       FROM immutable.checkpoints WHERE id = 1;" \
  | xargs -I{} echo -n '{}' | xxd -r -p > checkpoint_digest.bin

psql -h localhost -U postgres -d mydb -t -A \
  -c "SELECT encode(signature, 'hex')
       FROM immutable.checkpoints WHERE id = 1;" \
  | xargs -I{} echo -n '{}' | xxd -r -p > checkpoint_sig.bin

# 3. Verify externally (NO database connection needed from here on)
openssl pkeyutl -verify -pubin -inkey public.pem \
  -in checkpoint_digest.bin -sigfile checkpoint_sig.bin \
  -pkeyopt digest:sha256

# Expected output:
# "Signature Verified Successfully"
```

**What this proves:** The auditor does not need to trust the PostgreSQL server, connect to the database, or have any database credentials. They only need the checkpoint data, the public key, and the signature — all of which can be provided as an export document (via `export_checkpoint_for_verification()`).

### Public Key Fingerprint

Identify which key signed a checkpoint:

```sql
SELECT immutable.pgimmutable_rsa_pubkey_fingerprint(
  pg_read_file('/path/to/public.pem')
);
-- Returns: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
```

This is SHA-256 of the DER-encoded SubjectPublicKeyInfo (SPKI). Compare it against the fingerprint in `export_checkpoint_for_verification()` to match checkpoints to keys.

### API Reference

#### `immutable.pgimmutable_rsa_sign(key_pem TEXT, data BYTEA [, password TEXT]) → BYTEA`

Low-level C function. Signs arbitrary data with an RSA private key. Returns PKCS#1 v1.5 SHA-256 signature.

#### `immutable.pgimmutable_rsa_verify(pubkey_pem TEXT, data BYTEA, signature BYTEA) → BOOLEAN`

Low-level C function. Verifies an RSA signature. Returns `true` if valid.

#### `immutable.pgimmutable_rsa_pubkey_fingerprint(pubkey_pem TEXT) → TEXT`

Returns the SHA-256 fingerprint of an RSA public key as a hex string.

#### `immutable.checkpoint_sign_with_key(ckpt_id BIGINT, key_pem TEXT [, password TEXT]) → BOOLEAN`

Signs a checkpoint internally. ⚠️ Dev/test only.

#### `immutable.verify_checkpoint_signature(ckpt_id BIGINT, pubkey_pem TEXT) → BOOLEAN`

Verifies a checkpoint's signature using the provided public key.

#### `immutable.verify_external_checkpoint(checkpoint_json TEXT, signature BYTEA, pubkey_pem TEXT) → BOOLEAN`

Standalone verification — no database connection needed.

#### `immutable.key_help() → TABLE(step INT, instruction TEXT)`

Quick reference for external key generation and signing with OpenSSL CLI.

#### `immutable.verify_checkpoint_report(ckpt_id BIGINT, pubkey_pem TEXT) → TEXT`

Produces a comprehensive human-readable verification report for a signed checkpoint, mimicking the output of `scripts/verify_checkpoint.sh` but running entirely inside PostgreSQL.

**What the report includes:**

| Section | Content |
|---------|---------|
| **CHECKPOINT SUMMARY** | ID, database name/ID, checkpoint sequence, format version, creation/signing timestamps, table count |
| **TABLES IN CHECKPOINT** | Per-table chain heads (schema.table → chain_hash) |
| **CRYPTOGRAPHIC DETAILS** | Algorithm, SHA-256 digest hex, key fingerprint, signature status, signature hex |
| **VERDICT** | CLEAR PASS/FAIL or NOT SIGNED indicator |
| **EXTERNAL VERIFICATION INSTRUCTIONS** | Ready-to-run OpenSSL CLI commands for independent offline verification |

**Example:**
```sql
SELECT immutable.verify_checkpoint_report(1,
  pg_read_file('/var/lib/postgresql/16/main/public.pem')
);
```

**Example output:**
```
=== immutable Checkpoint Verification Report ===
============================================================
  CHECKPOINT SUMMARY
    ID              : 1
    Database        : mydb
    Database ID     : 16384
    Checkpoint Seq  : 1
    Format Version  : 1
    Created At      : 2026-07-27 15:13:30.418761+03
    Signed At       : 2026-07-27 15:14:00.123456+03
    Is Finalized    : t
    Tables Count    : 1
============================================================
  TABLES IN CHECKPOINT
    public.ledger  chain_head=e9212a2e16e5c02fbeca98b9a400f32e9beffcdb258d01385c81baee4f1e886d

============================================================
  CRYPTOGRAPHIC DETAILS
    Algorithm       : RSA-PKCS#1v1.5-SHA256
    SHA-256 Digest  : e9212a2e16e5c02fbeca98b9a400f32e9beffcdb258d01385c81baee4f1e886d
    Key Fingerprint  : d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
    Signature Status : VALID
    Signature (hex)  : a1b2c3d4...
============================================================
  VERDICT
  VERDICT: SIGNATURE VALID - checkpoint attests to this state
============================================================
  EXTERNAL VERIFICATION INSTRUCTIONS
    To verify this checkpoint independently without PostgreSQL:
    1. Save the digest and signature:
       echo -n 'e9212a2e...' | xxd -r -p > checkpoint_digest.bin
       echo -n 'a1b2c3d4...' | xxd -r -p > checkpoint.sig
    2. Save the public key to a file:
       # echo "-----BEGIN PUBLIC KEY-----..." > public_key.pem
    3. Run the verifier script:
       scripts/verify_checkpoint.sh checkpoint_export.txt public_key.pem

       Or use OpenSSL directly:
       openssl pkeyutl -verify -pubin -inkey public_key.pem \
         -in checkpoint_digest.bin -sigfile checkpoint.sig \
         -pkeyopt digest:sha256
============================================================
```

This function is useful for:
- Quick verification within a SQL session without needing external tools
- Automated monitoring scripts that call `psql -c` and grep for "SIGNATURE VALID"
- Generating reports for auditors while still connected to the database

### Standalone Verifier Script

`pg_immutable` ships a standalone bash script, `scripts/verify_checkpoint.sh`, that verifies checkpoint signatures using only OpenSSL CLI — **no PostgreSQL connection required**. An auditor can take a checkpoint export file and the public key, and independently verify authenticity.

**Features:**
- Parses both `export_checkpoint()` and `export_checkpoint_for_verification()` output formats
- Extracts the SHA-256 digest and RSA signature using `sed` and `grep`
- Verifies cryptographically using `openssl pkeyutl -verify` with pre-hashed data
- Clear exit codes: `0` = valid, `1` = invalid, `2` = error
- Self-contained temp file cleanup via `trap`

**Usage:**
```bash
./scripts/verify_checkpoint.sh <export_file> <public_key_pem>

# Example:
./scripts/verify_checkpoint.sh checkpoint_export.txt public_key.pem
# → Signature Verified Successfully
# → ✓ RESULT: SIGNATURE IS VALID
```

**End-to-end verification workflow:**
```bash
# 1. Export the checkpoint from PostgreSQL
psql -h localhost -U postgres -d mydb -t -A \
  -c "SELECT immutable.export_checkpoint(1);" \
  > checkpoint_export.txt

# 2. Copy the public key from secure storage
cp /path/to/public.pem ./

# 3. Verify entirely offline (no PostgreSQL)
./scripts/verify_checkpoint.sh checkpoint_export.txt public.pem
```

**Exit code handling:**
```bash
./scripts/verify_checkpoint.sh export.txt pubkey.pem
case $? in
  0) echo "Authentic" ;;
  1) echo "Tampered or wrong key" ;;
  2) echo "Error" ;;
esac
```

**Note on cryptography:** The C function `pgimmutable_rsa_sign` uses `EVP_PKEY_sign` with SHA-256 + PKCS#1 v1.5, which expects **pre-hashed** 32-byte data. The digest in the export file is already the SHA-256 hash of the checkpoint data. Therefore the script uses `openssl pkeyutl -verify` (not `openssl dgst -sha256 -verify`) to avoid double-hashing the input.

---

## 7. Other Functions

### `immutable.table_is_immutable(relid OID) → BOOLEAN`

Internal helper. Returns `true` if the given relation OID is registered as immutable and active.

---

## 8. C Extension Internals

### OpenSSL Signing Functions (New in v1.0)

Three C functions provide cryptographic signing for tamper-proof checkpoints:

#### `pgimmutable_rsa_sign(key_pem TEXT, data BYTEA [, password TEXT]) → BYTEA`

- Loads an RSA private key from a PEM string using `BIO_new_mem_buf` + `PEM_read_bio_PrivateKey`
- Creates an `EVP_PKEY_CTX` with SHA-256 digest and PKCS#1 v1.5 padding
- Calls `EVP_PKEY_sign()` in two passes: first to determine signature length, then to sign
- Returns the raw signature as BYTEA (256 bytes for a 2048-bit key)
- Supports optional password for encrypted private keys
- All OpenSSL resources (`BIO`, `EVP_PKEY`, `EVP_PKEY_CTX`) are freed before any `ereport(ERROR)` to prevent memory leaks

#### `pgimmutable_rsa_verify(pubkey_pem TEXT, data BYTEA, signature BYTEA) → BOOLEAN`

- Loads an RSA public key using `PEM_read_bio_PUBKEY` (SPKI format, as produced by `openssl rsa -pubout`)
- Creates verification context with matching SHA-256 + PKCS#1 v1.5 parameters
- `EVP_PKEY_verify()` returns: `1` = valid, `0` = invalid, `< 0` = error
- Returns `true` only on valid signature, `false` on mismatch, `ERROR` on OpenSSL error

#### `pgimmutable_rsa_pubkey_fingerprint(pubkey_pem TEXT) → TEXT`

- Encodes the public key to DER using `i2d_PUBKEY()`
- Computes SHA-256 of the DER-encoded SubjectPublicKeyInfo (SPKI)
- Returns the hex-encoded fingerprint (64 hex characters = 32 bytes)
- Used to identify which key signed a checkpoint; compare against the fingerprint in `export_checkpoint_for_verification()` output

All three functions use the OpenSSL EVP (Envelope) API which provides algorithm-independent operation and FIPS-compliant cryptographic primitives.

### `_PG_init()` — Module Initialization

Called when the library is loaded into a PostgreSQL backend (via `shared_preload_libraries` or `LOAD`).

**Responsibilities:**
1. Register GUC variables (`pg_immutable.enabled`, `pg_immutable.superuser_override`)
2. Install `ProcessUtility_hook` → `check_ddl_on_immutable_table()`
3. Install `planner_hook` → `check_dml_on_immutable_table()`

### `_PG_fini()` — Module Cleanup

Restores original hook pointers when the extension is unloaded.

### `check_ddl_on_immutable_table()` — DDL Hook

`ProcessUtility_hook` implementation. Intercepts and blocks:

| Statement | Result |
|-----------|--------|
| `DROP TABLE immutable_table` | `ERROR` |
| `TRUNCATE immutable_table` | `ERROR` |
| `ALTER TABLE immutable_table` (unsafe) | `ERROR` |
| `VACUUM FULL immutable_table` | `ERROR` |
| Safe ALTERs (SET STATISTICS, SET/RESET options) | Allowed |

**Superuser override:** If `pg_immutable.superuser_override = true` and the current user is a superuser, the operation is allowed but a `WARNING` is logged (leaving evidence of the bypass).

### `check_dml_on_immutable_table()` — DML Hook

`planner_hook` implementation. Intercepts during query planning (before execution):

| Statement | Result |
|-----------|--------|
| `UPDATE immutable_table` | `ERROR` |
| `DELETE FROM immutable_table` | `ERROR` |
| `MERGE INTO immutable_table` | `ERROR` |
| `INSERT INTO immutable_table` | Allowed (append-only) |

**Implementation detail:** Checks `parse->commandType` and inspects `parse->resultRelation` in the range table to identify the target relation.

### `table_is_immutable_internal()` — Registry Check

Queries `immutable.table_registry` via SPI to determine if a given OID belongs to a registered immutable table.

### `get_rel_oid()` — Name Resolution

Resolves a (schema, relation) name pair to a `relid` (OID). Uses `RangeVarGetRelid()` with `missing_ok = true`, falling back to `RelnameGetRelid()`.

### `hash_row_data()` — Row Hashing

Computes SHA-256 of a `HeapTuple`'s data portion. Iterates over all non-null, non-dropped attributes and hashes their binary representations. Uses `fastgetattr()` for attribute access and `get_typlenbyval()` for type metadata.

### `vacuumstmt_is_full()` — VACUUM FULL Detection

In PG 16, `VacuumStmt->options` is a `List *` of `DefElem` nodes. This function iterates through the list to find a `'full'` option with a truthy value.

### `bytes_to_hex()` — Hex Encoding

Converts binary bytes to a lowercase hex string (used for logging and building SPI query strings).

### `pgimmutable_hash_trigger()` — C Trigger (Reserved)

The C implementation of the hash chain trigger. Currently reserved for future optimization. The active implementation is the PL/pgSQL version in the SQL file.

> **Note:** The C trigger is kept as a reference for a more performant implementation. It uses OpenSSL's SHA-256 directly and SPI for database operations. However, it was replaced by the PL/pgSQL version due to reliability concerns with SPI management in the trigger context.

---

## 9. SQL Extension Internals

### Trigger: `immutable._chain_trigger_fn()`

The core per-row trigger, installed on every immutable table as a `BEFORE INSERT FOR EACH ROW` trigger.

**Algorithm:**
1. Serialize `NEW` row to JSON via `to_jsonb(NEW)::text`
2. Compute `row_hash = sha256(row_data::bytea)`
3. Query `immutable.hash_chain` for the latest entry for this table (using table alias to avoid PL/pgSQL variable collision)
4. If first entry: `chain_hash = sha256(row_hash || '1')`
5. If subsequent entry: `chain_hash = sha256(prev_chain_hash || row_hash || seq_no_text)`
6. Insert a new link into `immutable.hash_chain`

**Why PL/pgSQL over C:** The C trigger (`pgimmutable_hash_trigger`) had reliability issues with SPI connections and transaction management in the trigger context. The PL/pgSQL version is simpler, more maintainable, and fully reliable.

### Trigger Attachment: `immutable._attach_chain_trigger(relid OID)`

Creates the `immutable_hash_trigger` trigger on the specified table. Called by `create_immutable_table()` and `make_immutable()`.

### `immutable._hash_existing_rows(relid OID)`

Placeholder function for hashing existing rows when a table is retroactively made immutable. Currently returns a row count; in production this would iterate over all existing tuples and insert their hashes into the chain.

### `immutable.table_is_immutable(relid OID)`

SQL-callable function that queries `immutable.table_registry` for the given OID. Uses a simple `EXISTS` query.

---

## 10. Hash Chain Cryptography

### Chain Structure

```
Link 1 (first row):
  row_hash      = SHA-256( to_jsonb(row)::text::bytea )
  chain_hash    = SHA-256( row_hash || "1" )

Link N (subsequent rows):
  row_hash      = SHA-256( to_jsonb(row)::text::bytea )
  chain_hash    = SHA-256( prev_chain_hash || row_hash || seq_no_str )
```

### Properties

- **Tamper evidence:** Modifying any historical row changes its `row_hash`, which breaks all subsequent `chain_hash` values
- **Append-only integrity:** Deleting a row from the middle leaves a gap in `seq_no` that verification detects
- **Concurrency safety:** Each row's hash depends on the previous chain hash; the trigger's serial execution within a transaction prevents forks
- **Deterministic:** Same row data always produces the same `row_hash` (assuming same PostgreSQL JSON serialization)

### Verification Algorithm

```text
prev_hash := NULL
seq := 0

FOR EACH link IN hash_chain (ordered by seq_no ASC):
    IF seq == 0 AND link.prev_chain_hash IS NOT NULL:
        RETURN CHAIN_BROKEN
    
    IF seq > 0 AND (link.prev_chain_hash IS NULL OR link.prev_chain_hash != prev_hash):
        RETURN CHAIN_BROKEN
    
    expected := SHA-256( COALESCE(link.prev_chain_hash, '') || link.row_hash || link.seq_no::text )
    
    IF expected != link.chain_hash:
        RETURN CHAIN_BROKEN
    
    prev_hash := link.chain_hash
    seq := seq + 1

RETURN OK
```

---

## 11. Security Model

### Trust Boundary

```
┌─────────────────────────────────────────────────────────┐
│                PostgreSQL Data Plane                      │
│  ┌───────────────────────────────────────────────────┐   │
│  │ PostgreSQL Server                                  │   │
│  │  (Not trusted for long-term cryptographic proof)  │   │
│  └───────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                    ▲  ▲  ▲
                    │  │  │  Untrusted
────────────────────┼──┼──┼───────────────────────────────
                    │  │  │  Trusted
                    ▼  ▼  ▼
┌─────────────────────────────────────────────────────────┐
│              External Signing Authority                   │
│  ┌───────────────────────────────────────────────────┐   │
│  │  HSM / KMS / Isolated Signing Service             │   │
│  │  • Private key NEVER exposed to PostgreSQL        │   │
│  │  • Signs checkpoint digests on demand             │   │
│  │  • Provides independent verifiability             │   │
│  └───────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Key Principles

1. **Separation of Powers** — The database (PostgreSQL) handles storage and enforcement; an external authority (HSM/KMS) handles cryptographic signing.

2. **Tamper Evidence Over Tamper Prevention** — The system prioritizes making modifications detectable over preventing them absolutely (since a SUPERUSER with physical access can always bypass software controls).

3. **Defense in Depth** — Multiple layers (DDL hooks, DML hooks, hash chain, checkpoints, external signatures) ensure that bypassing any single layer does not compromise the overall integrity guarantee.

### What the System Guarantees

- Normal users cannot modify immutable records
- Privileged database users cannot modify immutable records through SQL
- A SUPERUSER bypass leaves cryptographic evidence
- Storage-level modifications are detectable via chain verification
- Database replacement is detectable via checkpoint verification
- Replay attacks are detectable via checkpoint sequence numbers

### What the System Cannot Guarantee

- Protection against OS `root` compromise
- Protection against physical server access
- Protection against HSM/KMS compromise
- Protection against private key compromise
- Protection against malicious PostgreSQL binary replacement

---

## 12. Threat Model

| ID | Threat Actor | Capabilities | Protection |
|----|-------------|--------------|------------|
| T1 | Normal User | Read/write permitted data | Blocked by DML hooks |
| T2 | Privileged User | Elevated SQL permissions | Blocked by DML hooks + hash chain |
| T3 | SUPERUSER | Full DB control | Hook enforcement + cryptographic evidence of override; cannot forge external signature |
| T4 | Malicious Extension | Execute privileged code | Cannot access private key; modifications detected by verification |
| T5 | Storage Attacker | Modify DB files | Detected by hash chain verification |
| T6 | Database Replacement | Create modified clone | Detected by checkpoint identity mismatch |
| T7 | Replay Attacker | Restore old snapshot | Detected by checkpoint sequence number |
| T8 | Key Compromise | Obtain private key | Mitigated by HSM/KMS; key rotation supported |

---

## 13. Development Guide

### Adding a New Function

1. **SQL function:** Add `CREATE OR REPLACE FUNCTION` to `pg_immutable--1.0.sql`
2. **C function:** Add the C implementation to `pg_immutable.c`, register with `PG_FUNCTION_INFO_V1`, and add a SQL wrapper in the SQL file
3. **Constants:** If shared constants are needed, add them to `pg_immutable.h`
4. **Build:** Run `make` to verify compilation
5. **Test:** Write integration tests and run against a test database

### PL/pgSQL Best Practices

- **Schema-qualify function calls:** Always use `immutable.verify()` not `verify()` when calling extension functions from within PL/pgSQL. PL/pgSQL resolves unqualified function names using the session's `search_path`, not the calling function's schema. This applies to all cross-schema calls, including calls to the C-backed signing functions (`immutable.pgimmutable_rsa_sign()`, etc.).
- **Use table aliases:** Always prefix column references with table aliases when variable names might collide with column names (e.g., `hc.chain_hash` instead of `chain_hash` when a PL/pgSQL variable named `chain_hash` exists).
- **Avoid variable-column name collisions in UPDATE:** When a PL/pgSQL variable shares a name with a table column, an `UPDATE ... SET col = var` statement becomes ambiguous. PostgreSQL may fail with "column reference is ambiguous". **Fix:** Use distinct variable names from column names (e.g., use `sig` not `signature` when the table has a `signature` column).
- **Explicit type casts:** When passing `NAME` values to functions expecting `TEXT`, use `::text` cast.
- **Return meaningful result codes:** Use integer status codes rather than just `SUCCESS`/`FAILURE` to distinguish error types.

### C Coding Conventions

- Follow PostgreSQL's `ereport()`/`elog()` error handling pattern
- Use `SPI_connect()`/`SPI_finish()` pairs for all database access
- Free allocated memory with `pfree()`
- Use `PG_TRY`/`PG_CATCH` for error handling in SPI contexts
- Register all global variables as GUCs via `DefineCustomBoolVariable()` etc.
- Hook functions must call `prev_hook()` or `standard_*()` as fallback

### Adding a New Hook

1. Declare a static function pointer for the previous hook:
   ```c
   static ProcessUtility_hook_type prev_ProcessUtility_hook = NULL;
   ```
2. Implement your hook function with the correct signature
3. In `_PG_init()`, save the previous hook and install yours:
   ```c
   prev_ProcessUtility_hook = ProcessUtility_hook;
   ProcessUtility_hook = my_hook_function;
   ```
4. In `_PG_fini()`, restore the previous hook:
   ```c
   ProcessUtility_hook = prev_ProcessUtility_hook;
   ```
5. Always call the previous hook (or `standard_*`) at the end of your handler

---

## 14. Testing Guide

### Quick Functional Test

```sql
-- Create extension
CREATE EXTENSION pg_immutable;

-- Create immutable table
SELECT immutable.create_immutable_table('public', 'ledger',
  'id SERIAL PRIMARY KEY, account_id INT NOT NULL, amount NUMERIC(12,2) NOT NULL, description TEXT'
);

-- Insert rows
INSERT INTO public.ledger (account_id, amount, description) VALUES (1001, 250.00, 'Deposit');
INSERT INTO public.ledger (account_id, amount, description) VALUES (1002, 500.00, 'Payment');

-- Verify chain (expect 0 = OK)
SELECT immutable.verify('public', 'ledger');

-- Check hash chain
SELECT seq_no, encode(row_hash, 'hex') AS row_hash,
       encode(chain_hash, 'hex') AS chain_hash
FROM immutable.hash_chain ORDER BY seq_no;

-- Create checkpoint
SELECT immutable.checkpoint_create();

-- Export checkpoint
SELECT immutable.export_checkpoint(1);

-- Verify all
SELECT * FROM immutable.verify_all();
```

### Comprehensive Test Suite

The following 16-test regression suite validates all functionality including signing:

| # | Test | Expected Outcome |
|---|------|------------------|
| 1 | `CREATE EXTENSION pg_immutable` | Extension created |
| 2 | `immutable.create_immutable_table(...)` | Table created and registered |
| 3 | `INSERT` 5 rows | Hash chain entries created |
| 4 | Check hash chain (`immutable.hash_chain`) | 5 entries with linked SHA-256 hashes |
| 5 | `immutable.verify()` | **0** (= OK, chain intact) |
| 6 | `immutable.verify_all()` | **OK** |
| 7 | `immutable.checkpoint_create()` | JSON with chain heads |
| 8 | `immutable.export_checkpoint()` | Non-empty export text |
| 9 | `immutable.make_immutable()` on existing table | Table registered with trigger |
| 10 | `immutable.verify_all()` (2 tables) | Both **OK** |
| 11 | `immutable.checkpoint_sign_with_key()` | **t** (signature stored) |
| 12a | `UPDATE` on immutable table | **ERROR** blocked by C hooks |
| 12b | `DELETE` on immutable table | **ERROR** blocked by C hooks |
| 12c | `TRUNCATE` on immutable table | **ERROR** blocked by C hooks |
| 12d | Rows preserved | 5 rows remain |
| 12e | `immutable.verify()` after hooks | **OK** (chain intact) |
| 13 | `immutable.verify_checkpoint_signature()` | **t** (signature valid) |
| 14 | `immutable.verify_external_checkpoint()` | **t** (no DB needed) |
| 15 | `immutable.export_checkpoint_for_verification()` | Complete auditor document |
| 16 | `immutable.key_help()` | 6-step instructions |
| 17 | `immutable.verify_checkpoint_report()` | Verification report with PASS/FAIL verdict |

### Automated Testing

```bash
# Create test database
createdb pg_immutable_test

# Run extension tests
psql -d pg_immutable_test -f /path/to/test_script.sql

# Clean up
dropdb pg_immutable_test
```

### Testing C Hooks (requires server restart)

```bash
# Add to postgresql.conf:
echo "shared_preload_libraries = 'pg_immutable'" >> /etc/postgresql/16/main/postgresql.conf

# Restart PostgreSQL
sudo systemctl restart postgresql

# Test blocking:
psql -d testdb -c "UPDATE ledger SET amount = 0 WHERE id = 1;"
# Expected: ERROR: cannot UPDATE immutable table

psql -d testdb -c "DROP TABLE ledger;"
# Expected: ERROR: cannot DROP immutable table
```

### Tamper Detection Demo

This demonstrates `pg_immutable`'s ability to cryptographically detect unauthorized modifications to the hash chain — even by a SUPERUSER with direct table access.

#### Setup

```sql
CREATE EXTENSION pg_immutable;

SELECT immutable.create_immutable_table('public', 'ledger',
  'id SERIAL PRIMARY KEY, account_id INT NOT NULL, amount NUMERIC(12,2) NOT NULL, description TEXT'
);

INSERT INTO public.ledger (account_id, amount, description) VALUES (1001, 250.00, 'Deposit');
INSERT INTO public.ledger (account_id, amount, description) VALUES (1002, 500.00, 'Payment');
INSERT INTO public.ledger (account_id, amount, description) VALUES (1003, 750.00, 'Transfer');
```

#### Phase 1 — Verify chain is intact

```sql
SELECT immutable.verify('public', 'ledger');
-- Returns: 0  (OK — chain intact)
```

#### Phase 2 — View the hash chain

```sql
SELECT seq_no, encode(chain_hash, 'hex') AS chain_hash
FROM immutable.hash_chain
ORDER BY seq_no;

-- Example output:
--  seq_no |                            chain_hash
-- --------+------------------------------------------------------------------
--       1 | 81e259f876e38b9f29a15a7a76a87d4290ec98b8676bb2fa8997cd122fbb19c7
--       2 | d8db7e2aae4eec5c5cae43bf18dc6a6f4e9965f747581ab4f05669a4f9105076
--       3 | 00802700b0903485b34ce08797ec49cca6ad0934c5fc1573975f263e617584df
```

Each `chain_hash` is computed as:
```text
chain_hash(N) = SHA-256( chain_hash(N-1) || row_hash(N) || seq_no_string )
```

#### Phase 3 — Simulate tampering (e.g., a SUPERUSER directly modifying the chain)

```sql
-- A malicious actor overwrites the chain_hash of seq_no=2
UPDATE immutable.hash_chain
SET chain_hash = decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hex')
WHERE seq_no = 2;
```

After tampering, the chain looks like:
```
-- seq_no |                            chain_hash
-- --------+------------------------------------------------------------------
--       1 | 81e259f876e38b9f29a15a7a76a87d4290ec98b8676bb2fa8997cd122fbb19c7
--       2 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ← TAMPERED
--       3 | 00802700b0903485b34ce08797ec49cca6ad0934c5fc1573975f263e617584df
```

#### Phase 4 — Detect the tampering

```sql
SELECT immutable.verify('public', 'ledger');
-- Returns: 1  (CHAIN_BROKEN — tampering DETECTED!)

SELECT * FROM immutable.verify_all();
-- schema | table_name |    status    |                           message
-- --------+------------+--------------+--------------------------------------------------------------
--  public | ledger     | CHAIN_BROKEN | Hash chain verification failed — possible tampering detected
```

#### Why it works

The verification algorithm walks the chain in `seq_no` order and recomputes each expected `chain_hash`:

```text
Link 1: expected = SHA-256( '' || row_hash_1 || '1' )
         → matches stored 81e259f8...  ✅

Link 2: expected = SHA-256( 81e2... || row_hash_2 || '2' )
         = d8db7e2a...
         → does NOT match stored aaaa...  ❌ CHAIN_BROKEN

Link 3: expected = SHA-256( d8db7e2a... || row_hash_3 || '3' )
         → prev_chain_hash check fails because
           stored prev = d8db7e2a... but link 2's stored chain_hash = aaaa...
         → CHAIN_BROKEN (cascading failure)
```

An attacker cannot silently modify the chain because altering any `chain_hash` breaks all downstream links. The only way to produce a valid chain after modification is to recompute every subsequent `chain_hash` — which requires access to the original `row_hash` values (which themselves chain to the modified data).

### Superuser Override Demo

This demonstrates the `pg_immutable.superuser_override` GUC, which allows a SUPERUSER to bypass immutability enforcement for emergency maintenance — while leaving forensic evidence.

#### Setup

```sql
CREATE EXTENSION pg_immutable;

SELECT immutable.create_immutable_table('public', 'ledger',
  'id SERIAL PRIMARY KEY, account_id INT NOT NULL, amount NUMERIC(12,2) NOT NULL, description TEXT'
);

INSERT INTO public.ledger (account_id, amount, description) VALUES (1001, 250.00, 'Deposit');
INSERT INTO public.ledger (account_id, amount, description) VALUES (1002, 500.00, 'Payment');
INSERT INTO public.ledger (account_id, amount, description) VALUES (1003, 750.00, 'Transfer');

SELECT immutable.verify('public', 'ledger');
-- Returns: 0  (OK — chain intact)
```

#### Phase 1 — UPDATE is blocked by default

```sql
UPDATE public.ledger SET amount = 0 WHERE id = 1;
-- ERROR: pg_immutable: cannot UPDATE immutable table (OID 2011613)
-- HINT:  Immutable tables are append-only. Insert a correction row instead.
```

#### Phase 2 — Enable superuser override

```sql
SET pg_immutable.superuser_override = on;
SHOW pg_immutable.superuser_override;
-- pg_immutable.superuser_override
-- ---------------------------------
-- on
```

#### Phase 3 — UPDATE succeeds with logged WARNING

```sql
UPDATE public.ledger SET amount = 0 WHERE id = 1;
-- WARNING:  pg_immutable: SUPERUSER OVERRIDE — UPDATE on immutable table OID 2011613
-- UPDATE 1
```

The `WARNING` is logged to PostgreSQL's server log, providing **forensic evidence** that the override was exercised.

#### Phase 4 — Data is modified

```sql
SELECT * FROM public.ledger ORDER BY id;
--  id | account_id | amount | description
-- ----+------------+--------+-------------
--   1 |       1001 |   0.00 | Deposit     ← amount changed from 250.00 to 0.00
--   2 |       1002 | 500.00 | Payment
--   3 |       1003 | 750.00 | Transfer
```

#### Phase 5 — Chain verification (note: the chain itself remains valid)

```sql
SELECT immutable.verify('public', 'ledger');
-- Returns: 0  (OK — chain intact)
```

The hash chain records INSERT operations only. The UPDATE modified row data without altering the chain, so the chain structure is intact — but the row data no longer matches the original `row_hash` values stored in the chain. Any checkpoint created before the override proves the original state.

#### Phase 6 — Disable override, blocking returns

```sql
SET pg_immutable.superuser_override = off;

UPDATE public.ledger SET amount = 0 WHERE id = 2;
-- ERROR: pg_immutable: cannot UPDATE immutable table (OID 2011613)
-- HINT:  Immutable tables are append-only. Insert a correction row instead.
```

#### Key takeaways

| Aspect | Detail |
|--------|--------|
| **Override GUC** | `pg_immutable.superuser_override` (boolean, default `off`) |
| **Who can set it** | Only `SUPERUSER` (`PGC_SUSET` context) |
| **Scope** | Session-level (`SET` not `SET LOCAL`; persists for the session) |
| **Evidence** | `WARNING` logged to PostgreSQL server log with OID of modified table |
| **Cryptographic impact** | Chain remains intact, but row data diverges from original `row_hash` values |
| **Forensic value** | Pre-override checkpoints prove original state; WARNING proves override occurred |

### Tamper + Signature Forensic Evidence Demo

This demonstrates how signed checkpoints act as **cryptographic time capsules** — proving the chain state at a specific point in time, even after tampering occurs.

#### Setup

```sql
CREATE EXTENSION pg_immutable;

SELECT immutable.create_immutable_table('public', 'ledger',
  'id SERIAL PRIMARY KEY, account_id INT NOT NULL, amount NUMERIC(12,2) NOT NULL, description TEXT'
);

INSERT INTO public.ledger (account_id, amount, description) VALUES (1001, 250.00, 'Deposit');
INSERT INTO public.ledger (account_id, amount, description) VALUES (1002, 500.00, 'Payment');
INSERT INTO public.ledger (account_id, amount, description) VALUES (1003, 750.00, 'Transfer');
```

#### Step 1 — Verify chain intact, create and sign checkpoint #1

```sql
SELECT immutable.verify('public', 'ledger');
-- Returns: 0  (OK)

SELECT immutable.checkpoint_create();             -- Checkpoint #1
SELECT immutable.checkpoint_sign_with_key(1,
  pg_read_file('/path/to/private.pem')
);
-- Returns: t  (signed)
```

Checkpoint #1 now cryptographically attests to the **original, untampered** chain state.

#### Step 2 — Verify checkpoint #1 signature

```sql
SELECT immutable.verify_checkpoint_signature(1,
  pg_read_file('/path/to/public.pem')
);
-- Returns: t  (signature is VALID)
```

#### Step 3 — Simulate tampering

```sql
-- A SUPERUSER or attacker directly modifies the hash chain
UPDATE immutable.hash_chain
SET chain_hash = decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hex')
WHERE seq_no = 2;
```

#### Step 4 — Verify detects tampering

```sql
SELECT immutable.verify('public', 'ledger');
-- Returns: 1  (CHAIN_BROKEN — tampering detected!)

SELECT * FROM immutable.verify_all();
-- schema | table_name |    status    |                           message
-- --------+------------+--------------+--------------------------------------------------------------
--  public | ledger     | CHAIN_BROKEN | Hash chain verification failed — possible tampering detected
```

#### Step 5 — Create and sign checkpoint #2 (attests to tampered state)

```sql
SELECT immutable.checkpoint_create();             -- Checkpoint #2
SELECT immutable.checkpoint_sign_with_key(2,
  pg_read_file('/path/to/private.pem')
);
-- Returns: t  (signed)
```

Checkpoint #2 attests to the **tampered** chain state.

#### Step 6 — Both checkpoint signatures are valid

```sql
SELECT immutable.verify_checkpoint_signature(1,
  pg_read_file('/path/to/public.pem')
);
-- Returns: t  (Checkpoint #1 — pre-tamper: attests to ORIGINAL state)

SELECT immutable.verify_checkpoint_signature(2,
  pg_read_file('/path/to/public.pem')
);
-- Returns: t  (Checkpoint #2 — post-tamper: attests to TAMPERED state)
```

Both signatures are cryptographically valid, but they attest to **different** chain states.

#### Step 7 — Export both checkpoints for comparison

```sql
SELECT immutable.export_checkpoint(1);  -- Pre-tamper chain_head
SELECT immutable.export_checkpoint(2);  -- Post-tamper chain_head
-- Note: chain_head may be the same if link 3 (the head) wasn't modified,
-- but the chain data differs internally
```

#### Timeline visualization

```
TIME ────────────────────────────────────────────────────────────►
         │                    │                      │
    Step 1               Step 3                Step 5
    verify = 0           TAMPER!               verify = 1
    CKPT #1 signed       hash overwritten      CKPT #2 signed
    │                    │                      │
    ▼                    ▼                      ▼
  ┌──────────┐       ┌──────────┐          ┌──────────┐
  │ Original │       │ TAMPERED │          │ TAMPERED │
  │ Chain    │       │ Chain    │          │ Chain    │
  │ State    │       │ State    │          │ State    │
  └──────────┘       └──────────┘          └──────────┘
         │                    │                      │
   CKPT #1 sig ✅      verify→1(🚨)          CKPT #2 sig ✅
```

#### Why this matters

| Item | What it proves |
|------|----------------|
| **Checkpoint #1 signature valid** | The checkpoint is authentic — signed by the private key holder at a specific time |
| **Checkpoint #1 chain_head** | Records the exact chain state BEFORE tampering — this is the **forensic baseline** |
| **`verify()` returns CHAIN_BROKEN** | The current chain does NOT match checkpoint #1's attested state |
| **Checkpoint #2 signature valid** | The post-tamper state is also authentic — tampering happened between CKPT #1 and CKPT #2 |

**Conclusion:** Checkpoints act as cryptographic time capsules. An auditor with checkpoint #1's export and the public key can independently verify that the original chain state was different from the current state — proving that tampering occurred after checkpoint #1 was signed. This is **separation of powers** in action: the database stores data, the external signature cryptographically proves when data was in a particular state.

---

## 15. Configuration Reference

### GUC Variables (set in `postgresql.conf` or via `SET`)

| Variable | Type | Default | Context | Description |
|----------|------|---------|---------|-------------|
| `pg_immutable.enabled` | `bool` | `true` | `PGC_SUSET` | Master switch for all enforcement |
| `pg_immutable.superuser_override` | `bool` | `false` | `PGC_SUSET` | Allow superuser to bypass checks (logs warning) |

Both require `SUPERUSER` to modify.

### Extension Control File (`pg_immutable.control`)

```
comment = 'Cryptographically verifiable record immutability for PostgreSQL'
default_version = '1.0'
module_pathname = '$libdir/pg_immutable'
relocatable = false
schema = immutable
```

- `relocatable = false` — The extension must be installed into the `immutable` schema
- `schema = immutable` — Forces all SQL objects into the `immutable` schema

### Makefile Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PG_CONFIG` | `pg_config` | Path to `pg_config` binary (for multi-PG-version setups) |
| `SHLIB_LINK` | `-lcrypto -lssl` | OpenSSL linkage |

Usage: `make PG_CONFIG=/usr/lib/postgresql/16/bin/pg_config`

---

## 16. Known Limitations

### Current

1. **C hooks require server restart:** `ProcessUtility_hook` and `planner_hook` only work when `pg_immutable` is loaded via `shared_preload_libraries`, which requires a PostgreSQL restart. Without this, UPDATE/DELETE/DROP are not blocked by the C layer.

2. **`_hash_existing_rows()` is a placeholder:** When an existing table is made immutable via `make_immutable()`, the function does not actually hash existing rows into the chain. Production use would require a C-based bulk hasher.

3. **JSON-based row hashing:** `to_jsonb(NEW)::text` is used for computing row hashes. This is deterministic within a PostgreSQL version but may change between versions. Future work could implement a binary-level hasher (the `hash_row_data()` C function is already available for this).

4. **PL/pgSQL trigger (not C):** The active trigger is implemented in PL/pgSQL for reliability, but the C implementation (`pgimmutable_hash_trigger`) is available as a higher-performance alternative once its SPI issues are resolved.

### Future Work

- C-based bulk hasher for existing rows
- KMS/HSM integration for automated signing
- Key rotation and revocation support
- WAL-level integration for stronger protection
- Binary-level row hashing for cross-version stability
- Regression test suite with `pg_regress`

---

*For the complete architecture plan and threat model, see [`pg_immutable_plan.md`](./pg_immutable_plan.md).*
