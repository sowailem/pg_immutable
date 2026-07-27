# pg_immutable — Cryptographically Verifiable Record Immutability for PostgreSQL

**pg_immutable** is a PostgreSQL extension that provides **cryptographically verifiable immutability** for database records. It enforces append-only semantics at the SQL level while maintaining a cryptographic SHA-256 hash chain that enables tamper detection — even against PostgreSQL `SUPERUSER` compromise.

---

## 🔬 Research Project

This extension is part of a Master's thesis:

**"Enhancing Digital Record Integrity Using Immutable Storage Techniques in Relational DBMS"**

**Researchers:** Mohammed Jafar Suleiman Al-Nahdi, Abdullah Ahmed Mahfoudh Sowailem  
**Supervisor:** PhD. Hamza Ali Al-Aidaroos

---

## 🚀 Quick Start

### Prerequisites

```bash
# PostgreSQL server development headers (adjust version to match your PG)
sudo apt-get install postgresql-server-dev-16

# OpenSSL development headers (for SHA-256 and RSA signing)
sudo apt-get install libssl-dev
```

### Build & Install

```bash
cd pg_immutable/

# Build
make PG_CONFIG=/usr/lib/postgresql/16/bin/pg_config

# Install (requires root)
sudo make install PG_CONFIG=/usr/lib/postgresql/16/bin/pg_config
```

### Enable in PostgreSQL

**For full protection (blocks UPDATE/DELETE/DROP):**

Edit `postgresql.conf`:
```ini
shared_preload_libraries = 'pg_immutable'
```

Then restart:
```bash
sudo systemctl restart postgresql
```

Then create the extension:
```sql
CREATE EXTENSION pg_immutable;
```

> Without `shared_preload_libraries`, the hash chain trigger and verification functions still work, but UPDATE/DELETE/DROP are not blocked at the C level.

### Create an Immutable Table

```sql
SELECT immutable.create_immutable_table('public', 'ledger',
  'id SERIAL PRIMARY KEY,
   account_id INT NOT NULL,
   amount NUMERIC(12,2) NOT NULL,
   description TEXT'
);
```

### Insert Data (auto-hashes every row)

```sql
INSERT INTO public.ledger (account_id, amount, description) VALUES (1001, 250.00, 'Deposit');
INSERT INTO public.ledger (account_id, amount, description) VALUES (1002, 500.00, 'Payment');
```

### Verify Chain Integrity

```sql
-- 0 = OK (chain intact), 1 = CHAIN_BROKEN
SELECT immutable.verify('public', 'ledger');

-- Verify all tables
SELECT * FROM immutable.verify_all();
```

### What Gets Blocked

```sql
UPDATE public.ledger SET amount = 0 WHERE id = 1;     -- ERROR
DELETE FROM public.ledger WHERE id = 1;                -- ERROR
DROP TABLE public.ledger;                              -- ERROR
TRUNCATE public.ledger;                                 -- ERROR
ALTER TABLE public.ledger ADD COLUMN x TEXT;            -- ERROR (unsafe ALTER)

INSERT INTO public.ledger ...                          -- ✅ Allowed (append-only)
```

### Create & Sign a Checkpoint

```bash
# 1. Generate RSA key pair (on a TRUSTED machine, never on the DB server)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

```sql
-- 2. Create checkpoint
SELECT immutable.checkpoint_create();

-- 3. Sign (DEV/TEST only — passes private key to PostgreSQL)
SELECT immutable.checkpoint_sign_with_key(1,
  pg_read_file('/path/to/private.pem')
);

-- 4. Verify signature
SELECT immutable.verify_checkpoint_signature(1,
  pg_read_file('/path/to/public.pem')
);
```

### Export & Verify Externally (No PostgreSQL)

```bash
# Export the checkpoint
psql -h localhost -U postgres -d mydb -t -A \
  -c "SELECT immutable.export_checkpoint(1);" > checkpoint_export.txt

# Verify using the standalone script (no DB connection needed)
./scripts/verify_checkpoint.sh checkpoint_export.txt public.pem
# → Signature Verified Successfully
# → ✓ RESULT: SIGNATURE IS VALID
```

---

## 🏗️ Architecture

### System Layers

```
┌──────────────────────────────────────────────────────────┐
│                    Application / Client                   │
├──────────────────────────────────────────────────────────┤
│                    PostgreSQL Data Plane                   │
│  ┌────────────────────────────────────────────────────┐   │
│  │                  pg_immutable                       │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  │   │
│  │  │ DDL Hook     │  │ DML Hook     │  │ Hash     │  │   │
│  │  │ (ProcessUtly)│  │ (Planner)    │  │ Chain    │  │   │
│  │  └─────────────┘  └──────────────┘  │ Trigger  │  │   │
│  │                                     └──────────┘  │   │
│  └────────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────────┤
│              External Signing Authority                    │
│  ┌────────────────────────────────────────────────────┐   │
│  │  HSM / KMS / Isolated Signing Service              │   │
│  │  (Private Key NEVER exposed to PostgreSQL)         │   │
│  └────────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────────┤
│               Cryptographic Trust Anchor                  │
│          (Independent Verification Possible)               │
└──────────────────────────────────────────────────────────┘
```

### Core Components

#### 1. DDL Protection (`ProcessUtility_hook`)

Intercepts and blocks destructive DDL on registered immutable tables:
- `DROP TABLE` — blocked
- `TRUNCATE` — blocked
- `ALTER TABLE` — blocked (except safe operations like `SET STATISTICS`)
- `VACUUM FULL` — blocked

#### 2. DML Protection (`planner_hook`)

Intercepts and blocks data modification:
- `UPDATE` — blocked, suggests inserting a correction row
- `DELETE` — blocked
- `MERGE` — blocked
- `INSERT` — allowed (append-only)

#### 3. Cryptographic Hash Chain (BEFORE INSERT trigger)

Each new row inserted into an immutable table triggers automatic SHA-256 hashing:

```
Chain Structure:
  Link 1: chain_hash = SHA-256( row_hash || "1" )
  Link 2: chain_hash = SHA-256( link1.chain_hash || row_hash || "2" )
  Link 3: chain_hash = SHA-256( link2.chain_hash || row_hash || "3" )
  ...
```

Modifying any historical record changes all subsequent hashes — tampering is **cryptographically detectable**.

#### 4. Checkpoint System

Snapshots the entire chain state into a JSON document that can be signed by an external authority:
- Captures chain heads for all registered tables
- Includes monotonically increasing sequence numbers (prevents rollback)
- Digest can be externally signed via HSM/KMS

#### 5. External Verification

Checkpoints can be exported and verified **without** PostgreSQL:
- `scripts/verify_checkpoint.sh` — standalone OpenSSL CLI verifier
- `immutable.verify_external_checkpoint()` — SQL function for cross-database verification

---

## 🔐 Security Model

### Trust Assumption

> PostgreSQL `SUPERUSER` privileges are not a sufficient trust boundary.
> A compromised PostgreSQL instance must not be able to forge a signed checkpoint without access to the external private key.

### What pg_immutable Protects Against

| Threat Actor | Protection |
|---|---|
| Normal database user | Blocked by DML hooks |
| Privileged user | Blocked by DML hooks + hash chain |
| SUPERUSER | Blocked by hooks; override leaves `WARNING` log evidence |
| Storage-level attacker | Detected by chain verification |
| Database replacement | Detected by checkpoint mismatch |
| Replay attack | Detected by checkpoint sequence numbers |

### Superuser Override

For emergency maintenance, a SUPERUSER can bypass enforcement:

```sql
SET pg_immutable.superuser_override = on;
UPDATE public.ledger SET amount = 0 WHERE id = 1;
-- WARNING: pg_immutable: SUPERUSER OVERRIDE — UPDATE on immutable table

SET pg_immutable.superuser_override = off;  -- Restore protection
```

The `WARNING` is logged to PostgreSQL's server log, providing forensic evidence.

### What pg_immutable Cannot Protect Against

- OS `root` compromising the signing key
- Physical server access
- HSM/KMS compromise
- Malicious replacement of the PostgreSQL binary

---

## 📋 API Overview

All functions live in the `immutable` schema:

| Function | Description |
|---|---|
| `immutable.create_immutable_table(schema, name, columns)` | Create a new immutable table |
| `immutable.make_immutable(schema, name)` | Mark existing table as immutable |
| `immutable.verify(schema, name)` → `INTEGER` | Verify hash chain (0=OK, 1=BROKEN) |
| `immutable.verify_all()` → `TABLE` | Verify all immutable tables |
| `immutable.checkpoint_create()` → `JSONB` | Snapshot chain state |
| `immutable.checkpoint_sign(id, hex)` | Store external signature |
| `immutable.checkpoint_sign_with_key(id, key_pem)` | Sign internally (dev only) |
| `immutable.verify_checkpoint_signature(id, pubkey)` | Verify signature |
| `immutable.verify_external_checkpoint(json, sig, pubkey)` | Verify without DB |
| `immutable.export_checkpoint(id)` → `TEXT` | Export checkpoint |
| `immutable.export_checkpoint_for_verification(id, pubkey)` → `TEXT` | Export with CLI commands |
| `immutable.key_help()` → `TABLE` | OpenSSL key generation reference |

---

## ⚙️ Configuration

| GUC | Default | Context | Description |
|---|---|---|---|
| `pg_immutable.enabled` | `on` | `PGC_SUSET` | Master switch for all enforcement |
| `pg_immutable.superuser_override` | `off` | `PGC_SUSET` | Allow SUPERUSER bypass (logs warning) |

Both require `SUPERUSER` to modify.

---

## 📁 Project Files

| File | Purpose |
|---|---|
| `pg_immutable.c` | C source: hooks, trigger, RSA signing |
| `pg_immutable.h` | Shared C constants and declarations |
| `pg_immutable--1.0.sql` | SQL functions, schema, tables |
| `Makefile` | PGXS build configuration |
| `scripts/verify_checkpoint.sh` | Standalone signature verifier (no PG needed) |
| `doc.md` | Full developer documentation |
| `pg_immutable_plan.md` | Architecture plan & threat model |

---

## 📖 Further Reading

- **[`doc.md`](./doc.md)** — Comprehensive developer documentation with API reference, testing guide, and external signing examples
- **[`pg_immutable_plan.md`](./pg_immutable_plan.md)** — Full architecture plan, threat model, and security design

---

## 📄 License

MIT License — Copyright (c) 2026 MAlnahdi
