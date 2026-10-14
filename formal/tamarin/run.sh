#!/bin/bash
# Prove the Tamarin model (~2 s per variant). Expected:
#   default  (prekey deleted on use, as in the app):
#            executable, one_code_one_session, injective_agreement,
#            first_message_secret — all "verified"
#   NOLOCK   (sanity check, prekey never deleted):
#            one_code_one_session and injective_agreement "falsified"
#            (a photographed or replayed bootstrap opens a second session)
# No wellformedness warning may appear. Maude helper processes are ended
# afterwards so nothing keeps running.
set -uo pipefail
cd "$(dirname "$0")"
for flags in "" "-D=NOLOCK"; do
  echo "== onetime ${flags:-(prekey deleted on use)}"
  perl -e 'alarm 600; exec @ARGV' tamarin-prover $flags --prove onetime.spthy 2>&1 \
    | grep -E "WARNING|verified|falsified|analysis incomplete"
  pkill -x maude 2>/dev/null || true
done
