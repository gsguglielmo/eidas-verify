#!/usr/bin/env bash
# Idempotently bootstrap the test corpora for eidas-verify.
#
# Usage: ./tools/sync-corpus.sh [--reset]
#
#   --reset   wipe the existing corpus checkout and re-clone from scratch
#
# This script is the canonical entry point for fetching the DSS test corpus
# and the NIST PKITS bundle. CI runs it before `cargo test --features
# corpus-dss,corpus-pkits,corpus-wycheproof`.
#
# Wycheproof vectors come bundled with the `wycheproof` crate (Apache-2.0)
# pulled via Cargo, so this script does not touch them.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_DIR="$REPO_ROOT/tests/vectors/dss-corpus"
SPARSE_FILE="$REPO_ROOT/tests/vectors/dss-corpus.sparse"
COMMIT_FILE="$REPO_ROOT/tests/vectors/dss-corpus.commit"
PKITS_DIR="$REPO_ROOT/tests/vectors/pkits"
PKITS_URL="https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip"
PKITS_DOC_URL="https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_v1_0_0.pdf"

reset=false
for arg in "$@"; do
  case "$arg" in
    --reset) reset=true ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# //'; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '[sync-corpus] %s\n' "$*"; }

if [[ "$reset" == true ]]; then
  log "wiping $CORPUS_DIR and $PKITS_DIR"
  rm -rf "$CORPUS_DIR" "$PKITS_DIR"
fi

# 1. DSS corpus — partial+sparse clone of esig/dss at the pinned commit.
sync_dss() {
  local commit
  commit="$(tr -d '[:space:]' < "$COMMIT_FILE")"
  : "${commit:?empty commit pin in $COMMIT_FILE}"

  if [[ ! -d "$CORPUS_DIR/.git" ]]; then
    log "clone esig/dss (partial, sparse) -> $CORPUS_DIR"
    git clone --filter=blob:none --no-checkout --depth 1 \
      --branch master \
      https://github.com/esig/dss.git "$CORPUS_DIR"
    git -C "$CORPUS_DIR" sparse-checkout init --no-cone
    cp "$SPARSE_FILE" "$CORPUS_DIR/.git/info/sparse-checkout"
    if [[ "$commit" != "master" ]]; then
      git -C "$CORPUS_DIR" fetch --depth 1 origin "$commit"
      git -C "$CORPUS_DIR" checkout "$commit"
    else
      git -C "$CORPUS_DIR" checkout master
    fi
  else
    log "refresh $CORPUS_DIR"
    cp "$SPARSE_FILE" "$CORPUS_DIR/.git/info/sparse-checkout"
    git -C "$CORPUS_DIR" sparse-checkout reapply
    if [[ "$commit" != "master" ]]; then
      git -C "$CORPUS_DIR" fetch --depth 1 origin "$commit" || true
      git -C "$CORPUS_DIR" checkout "$commit"
    else
      git -C "$CORPUS_DIR" pull --depth 1 origin master
    fi
  fi

  local size
  size="$(du -sh "$CORPUS_DIR" 2>/dev/null | cut -f1 || echo '?')"
  log "DSS corpus ready ($size, commit $(git -C "$CORPUS_DIR" rev-parse --short HEAD))"
}

# 2. NIST PKITS — public domain. Vendored zip extracted into tests/vectors/pkits/.
sync_pkits() {
  if [[ -d "$PKITS_DIR/certs" ]]; then
    log "PKITS already present ($(ls "$PKITS_DIR/certs" | wc -l) certs)"
    return
  fi
  if ! command -v curl >/dev/null; then
    log "curl missing, skipping PKITS"
    return
  fi
  mkdir -p "$PKITS_DIR"
  log "fetching PKITS from $PKITS_URL"
  curl -fsSL "$PKITS_URL" -o "$PKITS_DIR/PKITS_data.zip"
  curl -fsSL "$PKITS_DOC_URL" -o "$PKITS_DIR/PKITS_v1_0_0.pdf" || true
  if command -v unzip >/dev/null; then
    unzip -q -o "$PKITS_DIR/PKITS_data.zip" -d "$PKITS_DIR"
  else
    log "unzip missing — leaving PKITS_data.zip in place; install unzip and re-run"
    return
  fi
  log "PKITS ready"
}

sync_dss
sync_pkits
log "done"
