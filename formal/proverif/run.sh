#!/bin/bash
# Run every scenario of the LADON messenger ProVerif models.
# Scenario lines in a model are written (*@name ... @*); a variant switches
# on exactly the listed names and leaves every other scenario line a comment.
# Usage: ./run.sh            (all models, all scenarios)
set -euo pipefail
cd "$(dirname "$0")"
PROVERIF="${PROVERIF:-proverif}"
OUT="${OUT:-/tmp/ladon-proverif}"
mkdir -p "$OUT"

variant() {   # variant <model> <label> [scenario names...]
  local model="$1" label="$2"; shift 2
  local f="$OUT/${model%.pv}-${label}.pv"
  cp "$model" "$f"
  for name in "$@"; do
    sed -i '' -E "s/\(\*@${name} (.*) @\*\)/\1/g" "$f"
  done
  echo "== ${model%.pv} / ${label}"
  "$PROVERIF" "$f" 2>&1 | grep -E "^(RESULT|Error|File)" || true
}

# Bootstrap. Expected: secretA secret and Bob's acceptance authentic in base,
# dh-broken, kem-broken and longterm-leak; both-broken — secretA readable
# (sanity check: the model does find attacks). one-time — "cannot be proved":
# ProVerif abstracts the deletion of the prekey (state) and cannot prove that
# one code opens at most one session; without the deletion (drop the lock) it
# reports the concrete attack, so the property rests on that deletion, which
# the app's device self-tests check (testV2BootSecondUseRejected & co.).
variant bootstrap.pv base
variant bootstrap.pv dh-broken dh
variant bootstrap.pv kem-broken kem
variant bootstrap.pv both-broken dh kem
variant bootstrap.pv longterm-leak fs
variant bootstrap.pv one-time lock

# Ratchet. Expected: base and fs — all messages secret. pcs — m2 readable
# (the attacker holds Bob's state for that turn), m3 secret again (healed).
# pcs + dh / pcs + kem — m3 still secret (either primitive heals alone).
# pcs + dh + kem — m3 readable (sanity check: nothing left to heal with).
variant ratchet.pv base
variant ratchet.pv forward-secrecy fs
variant ratchet.pv compromise-heals pcs
variant ratchet.pv heals-dh-broken pcs dh
variant ratchet.pv heals-kem-broken pcs kem
variant ratchet.pv heals-both-broken pcs dh kem
