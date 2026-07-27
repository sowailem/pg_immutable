#!/usr/bin/env bash
# ========================================================================
# verify_checkpoint.sh — Standalone pg_immutable Checkpoint Verifier
#
# Verifies the cryptographic signature of a pg_immutable checkpoint
# export using only OpenSSL CLI — no PostgreSQL connection required.
#
# An auditor can take a checkpoint export file (from
# export_checkpoint_for_verification()) and the signer's public key,
# and independently verify that the checkpoint data is authentic and
# unmodified.
#
# Usage:
#   ./verify_checkpoint.sh <export_file> <public_key_pem>
#
# Arguments:
#   export_file    — Path to the checkpoint export text file
#                    (output of export_checkpoint() or
#                     export_checkpoint_for_verification())
#   public_key_pem — Path to the RSA public key in PEM format
#
# Exit codes:
#   0 — Signature is VALID (Verified OK)
#   1 — Signature is INVALID (data or signature tampered)
#   2 — Error (missing files, bad format, etc.)
#
# Example:
#   ./verify_checkpoint.sh checkpoint_export.txt public_key.pem
#   → ✓ Verified OK — checkpoint is authentic
#
# Dependencies:
#   - openssl (with RSA/SHA256 support)
#   - xxd (for hex-to-binary conversion)
#   - grep, sed, mktemp (standard POSIX tools)
#
# Copyright (c) 2026 MAlnahdi
# MIT License
# ========================================================================

set -euo pipefail

# --- Constants -----------------------------------------------------------

SCRIPT_NAME=$(basename "$0")

# --- Functions -----------------------------------------------------------

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <export_file> <public_key_pem>

Verifies a pg_immutable checkpoint signature using OpenSSL CLI.

Arguments:
  export_file       Path to the checkpoint export text file
                    (output of export_checkpoint() or
                     export_checkpoint_for_verification())
  public_key_pem    Path to the RSA public key in PEM format

Exit codes:
  0   Signature is VALID
  1   Signature is INVALID
  2   Error (missing files, bad format, etc.)

Example:
  ${SCRIPT_NAME} checkpoint_export.txt public_key.pem
EOF
    exit 2
}

die() {
    echo "ERROR: $*" >&2
    exit 2
}

cleanup() {
    if [[ -n "${TMPDIR:-}" && -d "$TMPDIR" ]]; then
        rm -rf "$TMPDIR"
    fi
}

# --- Parse Arguments -----------------------------------------------------

if [[ $# -lt 2 ]]; then
    usage
fi

EXPORT_FILE="$1"
PUBKEY_FILE="$2"

# --- Validate Inputs -----------------------------------------------------

if [[ ! -f "$EXPORT_FILE" ]]; then
    die "Export file not found: $EXPORT_FILE"
fi

if [[ ! -f "$PUBKEY_FILE" ]]; then
    die "Public key file not found: $PUBKEY_FILE"
fi

# Verify public key is valid PEM
if ! openssl pkey -pubin -in "$PUBKEY_FILE" -noout 2>/dev/null; then
    die "Public key file is not a valid PEM public key: $PUBKEY_FILE"
fi

# --- Create Temporary Directory ------------------------------------------

TMPDIR=$(mktemp -d "/tmp/pg_immutable_verify.XXXXXX")
trap cleanup EXIT INT TERM

DIGEST_FILE="${TMPDIR}/digest.bin"
SIG_FILE="${TMPDIR}/signature.bin"

# --- Extract Data from Export File ---------------------------------------

# Strategy: Parse the export file to find:
#   1. The SHA-256 Digest (hex) — the exact bytes that were signed
#   2. The Digital Signature (hex) — the RSA signature

# Extract the SHA-256 digest hex value.
# The export format has sections like:
#   --- SHA-256 Digest To Verify (hex) ---
#   1fc85be6d72c92ea29629858076f4e1e...  (the hex digest)
#
# Or from export_checkpoint_for_verification():
#   --- SHA-256 Digest (hex) ---
#   1fc85be6d72c92ea29629858076f4e1e...

DIGEST_HEX=$(sed -n '/SHA-256 Digest/{n;p}' "$EXPORT_FILE" | \
             tr -d '[:space:]' | \
             grep -E '^[0-9a-fA-F]{64}$' | head -1)

if [[ -z "$DIGEST_HEX" ]]; then
    die "Could not find SHA-256 digest in export file. Is this a valid checkpoint export?"
fi

# Extract the signature hex value.
# The export format has a section like:
#   --- Digital Signature (hex) ---
#   388b9ed91290a2297cc79519e420a905... (the hex signature)
#
# Or from the basic export:
#   --- Signature (hex) ---  (in export_checkpoint)

# First, check if the checkpoint is signed (the export says "(not signed)" otherwise)
RAW_SIG_LINE=$(sed -n '/Signature (hex)/{n;p}' "$EXPORT_FILE" | head -1)
if echo "$RAW_SIG_LINE" | tr -d '[:space:]' | grep -qi "not.signed"; then
    die "Checkpoint has NOT been signed. Cannot verify an unsigned checkpoint."
fi

SIG_HEX=$(echo "$RAW_SIG_LINE" | \
          tr -d '[:space:]' | \
          grep -E '^[0-9a-fA-F]{64,}$' | head -1)

if [[ -z "$SIG_HEX" ]]; then
    die "Could not find digital signature in export file. Has this checkpoint been signed?"
fi

# --- Convert Hex to Binary -----------------------------------------------

echo "--- Parsing checkpoint export: $(basename "$EXPORT_FILE")"

# Convert digest hex to binary
if ! echo -n "$DIGEST_HEX" | xxd -r -p > "$DIGEST_FILE" 2>/dev/null; then
    die "Failed to convert digest hex to binary — is xxd installed?"
fi

DIGEST_LEN=$(wc -c < "$DIGEST_FILE")
echo "  SHA-256 digest : ${DIGEST_HEX:0:32}... (${DIGEST_LEN} bytes)"

# Convert signature hex to binary
if ! echo -n "$SIG_HEX" | xxd -r -p > "$SIG_FILE" 2>/dev/null; then
    die "Failed to convert signature hex to binary — is xxd installed?"
fi

SIG_LEN=$(wc -c < "$SIG_FILE")
echo "  Signature      : ${SIG_HEX:0:32}... (${SIG_LEN} bytes)"
echo "  Public key     : $(basename "$PUBKEY_FILE")"

# Verify digest length (SHA-256 is 32 bytes)
if [[ "$DIGEST_LEN" -ne 32 ]]; then
    die "Invalid digest length: ${DIGEST_LEN} bytes (expected 32 bytes for SHA-256)"
fi

echo ""

# --- Perform Verification ------------------------------------------------

# OpenSSL verification uses pkeyutl because the data is PRE-HASHED.
#
# The pgimmutable_rsa_sign C function expects the input to be exactly 32 bytes
# (the SHA-256 digest). Internally it uses EVP_PKEY_sign with SHA-256 and
# PKCS#1 v1.5, which expects pre-hashed data of exactly the digest length.
#
# Therefore, the digest.bin file contains the RAW 32-byte SHA-256 hash, NOT
# the original checkpoint data. We must use pkeyutl -verify (not dgst -verify)
# to avoid OpenSSL hashing the input again.
#
# Command:
#   openssl pkeyutl -verify -pubin -inkey pubkey.pem \
#     -in digest.bin -sigfile sig.bin \
#     -pkeyopt digest:sha256
#
# Exit code:
#   0 = Signature Verified Successfully
#   1 = Verification failure (signature does NOT match)

echo "--- Verifying signature with OpenSSL ---"
echo ""

set +e  # Allow OpenSSL to fail without killing the script
openssl pkeyutl -verify \
    -pubin \
    -inkey "$PUBKEY_FILE" \
    -in "$DIGEST_FILE" \
    -sigfile "$SIG_FILE" \
    -pkeyopt digest:sha256 2>&1

OPENSSL_EXIT=$?
set -e

echo ""

# --- Report Result -------------------------------------------------------

if [[ $OPENSSL_EXIT -eq 0 ]]; then
    echo "✓ RESULT: SIGNATURE IS VALID — checkpoint data is authentic and unmodified."
    echo ""
    echo "  The checkpoint was created by the holder of the private key"
    echo "  corresponding to the provided public key."
    exit 0
elif [[ $OPENSSL_EXIT -eq 1 ]]; then
    echo "✗ RESULT: SIGNATURE IS INVALID — checkpoint data has been tampered with"
    echo "  OR was signed by a different private key."
    echo ""
    echo "  Possible causes:"
    echo "    - The checkpoint data was modified after signing"
    echo "    - The wrong public key was provided"
    echo "    - The signature was corrupted"
    exit 1
else
    echo "ERROR: OpenSSL verification failed with unexpected exit code ${OPENSSL_EXIT}."
    exit 2
fi
