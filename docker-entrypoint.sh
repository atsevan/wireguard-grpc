#!/bin/sh
ip link add dev wg0 type wireguard
ip address add 10.7.0.1/24 dev wg0
ip link set up dev wg0
exec /wireguard-grpc "$@"
