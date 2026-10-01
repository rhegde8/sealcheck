#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

command -v docker >/dev/null || { echo 'Docker with Compose is required for the Linux isolation lab.' >&2; exit 2; }
test -x bin/sealcheck || { echo 'Run make build first.' >&2; exit 2; }
SEALCHECK_WITNESS_TOKEN="$(openssl rand -hex 24)"
export SEALCHECK_WITNESS_TOKEN
out="out/lab-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
bin/sealcheck keygen --private-key "$out/controller.key.pem" --public-key "$out/controller.pub.pem"
compose() { docker compose -f lab/compose.yaml "$@"; }
cleanup() { compose down --remove-orphans >/dev/null; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

compose up --build -d

# Wait from the trusted host; no witness credentials are passed to the runner.
ready() {
  for port in 18081 18082; do
    tries=0
    until curl --silent --fail --noproxy '*' -H "Authorization: Bearer $SEALCHECK_WITNESS_TOKEN" "http://127.0.0.1:$port/health" >/dev/null; do
      tries=$((tries + 1))
      if [ "$tries" -ge 30 ]; then echo 'Witness startup failed.' >&2; return 2; fi
      sleep 1
    done
  done
  tries=0
  until compose exec -T --user 10001:10001 sandbox sh -c 'grep -q "^Uid:[[:space:]]*10001" /proc/1/status'; do
    tries=$((tries + 1))
    if [ "$tries" -ge 30 ]; then echo 'Sandbox initialization failed.' >&2; return 2; fi
    sleep 1
  done
}

# check PHASE EXPECTED_EXIT [POLICY] [reference]
check() {
  phase="$1"
  expected="$2"
  policy="${3:-lab/policy.json}"
  use_reference="${4:-}"
  container="$(compose ps -q sandbox)"
  set -- --policy "$policy" --private-key "$out/controller.key.pem" --out "$out/$phase"
  if [ "$use_reference" = reference ]; then
    set -- "$@" --reference-launcher "[\"docker\",\"exec\",\"-i\",\"$(compose ps -q reference)\",\"sealcheck\",\"probe\"]"
  fi
  set +e
  bin/sealcheck check "$@" -- \
    docker exec -i --user 0 "$container" \
    setpriv --reuid 10001 --regid 10001 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs sealcheck probe
  actual=$?
  set -e
  if [ "$actual" -ne "$expected" ]; then echo "$phase: expected exit $expected, got $actual" >&2; exit 2; fi
}

ready
check baseline 0
docker compose -f lab/compose.yaml -f lab/leaky.yaml up -d --no-deps proxy
ready
check proxy-leak 1
compose up -d --no-deps --force-recreate proxy
ready
check remediated 0

# Demonstrate real direct transport leaks independently of proxy fixtures.
compose exec -T --user 0 sandbox ip route del prohibit 172.30.56.30/32
compose exec -T --user 0 sandbox ip -6 route del prohibit fd53:ea1:56::30/128
check direct-leak 1
compose exec -T --user 0 sandbox ip route add prohibit 172.30.56.30/32
compose exec -T --user 0 sandbox ip -6 route add prohibit fd53:ea1:56::30/128
check restored 0

# EHOSTUNREACH blocks delivery but, unlike prohibit's EACCES, does not prove a
# policy denial. Explicit-only evidence stays INCONCLUSIVE; the non-receipt
# policy passes once the reference context proves each target live.
compose exec -T --user 0 sandbox ip route replace unreachable 172.30.56.30/32
compose exec -T --user 0 sandbox ip -6 route replace unreachable fd53:ea1:56::30/128
check unreachable-explicit 2
check unreachable-non-receipt 0 lab/policy-nonreceipt.json reference

# Non-receipt mode must not mask a real leak.
compose exec -T --user 0 sandbox ip route del unreachable 172.30.56.30/32
compose exec -T --user 0 sandbox ip -6 route del unreachable fd53:ea1:56::30/128
check non-receipt-leak 1 lab/policy-nonreceipt.json reference
compose exec -T --user 0 sandbox ip route add prohibit 172.30.56.30/32
compose exec -T --user 0 sandbox ip -6 route add prohibit fd53:ea1:56::30/128
check non-receipt-restored 0 lab/policy-nonreceipt.json reference
echo "Verified baseline, proxy leak, remediation, direct leaks, restoration, and non-receipt grading. Reports: $out"
