#!/bin/sh
set -eu

# Route prohibition generates EACCES in the actual workload network namespace.
# DROP would instead require independent denial telemetry to justify PASS.
ip route replace prohibit 172.30.56.30/32
ip route replace prohibit default
ip -6 route replace prohibit fd53:ea1:56::30/128
ip -6 route replace prohibit default
ip rule add priority 10 ipproto tcp dport 8081 prohibit
ip -6 rule add priority 10 ipproto tcp dport 8081 prohibit

# Use the controlled authoritative resolver directly instead of Docker's DNS
# stub, which is an additional forwarding boundary and deserves a separate test.
printf 'nameserver 172.30.56.30\noptions timeout:1 attempts:1\n' > /etc/resolv.conf

exec setpriv --reuid 10001 --regid 10001 --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
  --no-new-privs sleep infinity
