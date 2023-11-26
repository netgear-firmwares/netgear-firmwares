#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, no IPs assigned, all unhealthy"

export CTDB_TEST_LOGLEVEL=ERR

required_result <<EOF
192.168.21.254 0
192.168.21.253 1
192.168.21.252 2
192.168.20.254 0
192.168.20.253 1
192.168.20.252 2
192.168.20.251 0
192.168.20.250 1
192.168.20.249 2
EOF

simple_test 2,2,2 <<EOF
192.168.21.254 -1
192.168.21.253 -1
192.168.21.252 -1
192.168.20.254 -1
192.168.20.253 -1
192.168.20.252 -1
192.168.20.251 -1
192.168.20.250 -1
192.168.20.249 -1
EOF
