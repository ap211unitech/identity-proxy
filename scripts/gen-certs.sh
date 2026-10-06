#!/usr/bin/env bash
# Generates throw-away test certificates into ./certs (never use these in production).
set -euo pipefail
mkdir -p certs && cd certs
KEY="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"

mk_ca() {  # mk_ca <name>
  openssl req -x509 $KEY -keyout "$1.key" -out "$1.pem" -days 30 -subj "/CN=$1" 2>/dev/null
}
mk_leaf() {  # mk_leaf <name> <EKU> <extra extension line or ""> <signing CA>
  openssl req -new $KEY -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
  printf 'extendedKeyUsage=%s\n%s\n' "$2" "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$4.pem" -CAkey "$4.key" -CAcreateserial \
    -days 30 -extfile "$1.ext" -out "$1.pem" 2>/dev/null
}

mk_ca ca            # trust store v1
mk_ca ca-v2         # trust store v2 (used to demo rotation)
mk_ca rogue-ca      # never trusted

mk_leaf server serverAuth "subjectAltName=DNS:localhost,IP:127.0.0.1" ca
mk_leaf client-payment   clientAuth "subjectAltName=URI:spiffe://acme/prod/payment-agent"   ca
mk_leaf client-reporting clientAuth "subjectAltName=URI:spiffe://acme/prod/reporting-agent" ca
mk_leaf client-other     clientAuth "subjectAltName=URI:spiffe://acme/prod/other-agent"     ca
mk_leaf client-bad-spiffe clientAuth "subjectAltName=URI:spiffe://acme"                     ca  # malformed
mk_leaf client-no-san    clientAuth "" ca                                                       # no identity
mk_leaf client-rogue     clientAuth "subjectAltName=URI:spiffe://acme/prod/payment-agent" rogue-ca  # untrusted
mk_leaf client-v2        clientAuth "subjectAltName=URI:spiffe://acme/prod/payment-agent" ca-v2     # only valid after rotation

# Expired client cert (needs `openssl ca` to back-date).
cat > expired.cnf <<CNF
[ca]
default_ca = d
[d]
database = index.txt
new_certs_dir = .
serial = serial.txt
default_md = sha256
policy = p
unique_subject = no
x509_extensions = x
[p]
commonName = supplied
[x]
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://acme/prod/payment-agent
CNF
: > index.txt; echo 01 > serial.txt
openssl req -new $KEY -keyout client-expired.key -out client-expired.csr -subj "/CN=client-expired" 2>/dev/null
openssl ca -config expired.cnf -cert ca.pem -keyfile ca.key -in client-expired.csr -out client-expired.pem \
  -startdate 20240101000000Z -enddate 20240102000000Z -batch -notext 2>/dev/null

# Proxy's client trust bundle starts as CA v1.
cp ca.pem client-ca.pem
chmod a+r *.key   # test keys only: lets the non-root container user read them
echo "certificates written to $(pwd)"
