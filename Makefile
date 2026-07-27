# Makefile for pg_immutable PostgreSQL extension
# Uses PostgreSQL's PGXS build system
#
# Requirements:
#   - PostgreSQL server development headers (postgresql-server-dev-18)
#   - OpenSSL development headers (libssl-dev)
#
# Build:
#   make          # compile
#   make install  # install into PostgreSQL's extension directory
#
# Test:
#   make installcheck  # runs pg_regress tests (if any)
#
# Copyright (c) 2026 MAlnahdi
# MIT License

EXTENSION    = pg_immutable
MODULE_big   = pg_immutable
OBJS         = pg_immutable.o

# Data files (SQL script and control file)
DATA         = pg_immutable--1.0.sql

# Extension control file
EXTRA_CLEAN  = pg_immutable.o

# PGXS configuration
PG_CONFIG    = pg_config
PGXS         := $(shell $(PG_CONFIG) --pgxs)

# OpenSSL
SHLIB_LINK  += -lcrypto -lssl

# Include PGXS
include $(PGXS)

# Add OpenSSL include path via PG_CPPFLAGS (PGXS-safe)
PG_CPPFLAGS += $(shell pkg-config --cflags openssl 2>/dev/null || echo "-I/usr/include/openssl")
