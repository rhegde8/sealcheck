#!/bin/sh
set -eu

# Route prohibition generates EACCES in the actual workload network namespace.
# DROP would instead require independent denial telemetry to justify PASS.
ip route replace prohibit 172.30.56.30/32
ip route replace prohibit default
ip -6 route replace prohibit fd53:ea1:56::30/128
ip -6 route replace prohibit default
# TCP is protocol 6; the minimal image has no /etc/protocols name database.
ip rule add priority 10 ipproto 6 dport 8081 prohibit
ip -6 rule add priority 10 ipproto 6 dport 8081 prohibit

# Compose mounts the controlled resolver configuration read-only. Docker's DNS
# stub is an additional forwarding boundary and deserves a separate test.

exec setpriv --reuid 10001 --regid 10001 --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
  --no-new-privs sleep infinity
