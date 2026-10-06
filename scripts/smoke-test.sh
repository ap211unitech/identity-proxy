#!/usr/bin/env bash
# End-to-end checks. Needs the proxy on :8443 and the mock upstream on :8080 (see README).
cd "$(dirname "$0")/../certs"
URL=https://localhost:8443
fails=0

check() {  # check <description> <expected http code (000 = TLS failure)> <curl args...>
  local desc=$1 want=$2; shift 2
  local got
  got=$(curl -s -o /dev/null -w '%{http_code}' --cacert ca.pem "$@" 2>/dev/null)
  if [ "$got" = "$want" ]; then echo "PASS  $desc ($got)"; else echo "FAIL  $desc: want $want got $got"; fails=$((fails+1)); fi
}
as() { echo --cert client-$1.pem --key client-$1.key; }   # curl args for a client cert

check "payment-agent POST /payments allowed"      200 $(as payment)   -X POST $URL/payments
check "payment-agent GET /payments denied"        403 $(as payment)   $URL/payments
check "payment-agent POST /reports/q1 denied"     403 $(as payment)   -X POST $URL/reports/q1
check "reporting-agent GET /reports/q1 allowed"   200 $(as reporting) "$URL/reports/q1?x=1"
check "reporting-agent GET /reports (no wildcard) denied" 403 $(as reporting) $URL/reports
check "unlisted identity denied"                  403 $(as other)     $URL/reports/q1
check "path traversal rejected"                   400 $(as reporting) --path-as-is $URL/reports/../payments
check "encoded slash rejected"                    400 $(as reporting) --path-as-is $URL/reports/a%2f..%2fpayments
check "malformed SPIFFE id rejected (app layer)"  401 $(as bad-spiffe) $URL/reports/q1
check "cert without identity rejected (app layer)" 401 $(as no-san)   $URL/reports/q1
check "no client cert rejected (TLS layer)"       000 $URL/reports/q1
check "untrusted CA rejected (TLS layer)"         000 $(as rogue)     $URL/reports/q1
check "expired cert rejected (TLS layer)"         000 $(as expired)   $URL/reports/q1
check "proxy loop rejected"                       508 $(as reporting) -H "Via: 1.1 identity-proxy" $URL/reports/q1
check "oversized body rejected (limit 1 MiB)"     413 $(as payment)   -X POST --data-binary @<(head -c 2000000 /dev/zero) $URL/payments
check "health endpoint"                           200 http://localhost:8081/healthz

echo; echo "--- what the upstream saw (headers set/sanitised by the proxy; spoofed ones dropped) ---"
curl -s --cacert ca.pem $(as reporting) -H 'X-Forwarded-For: 6.6.6.6' -H 'X-Authenticated-Identity: spiffe://acme/admin' \
  -H 'Connection: close, X-Secret' -H 'X-Secret: hop' $URL/reports/q1; echo
[ $fails -eq 0 ] && echo "ALL PASSED" || { echo "$fails FAILED"; exit 1; }
