#!/bin/bash

# Copyright 2015 Google Inc. All rights reserved.
# Updated for the Rust rewrite, 2026.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

DUMMY="${DUMMY-dummy0}"
DIR="$(mktemp -d)"
SOCKET="$DIR/socket"
CONFIG="$DIR/config"

set -e
cd $(dirname $0)
REPO_ROOT="$(cd .. && pwd)"
RUST_BIN="${REPO_ROOT}/rust/target/release"

function Log {
  FORMAT=$1
  shift
  echo -e "${FORMAT}$(date +%H:%M:%S.%N) --- $@\e[0m"
}
function Info { Log "\e[7m"  "$@"; }
function Error { Log "\e[41m" "$@"; }
function Die {
  Error "$@"
  for file in `find $DIR -type f | sort`; do
    Info "$file"
    cat $file
  done
  exit 1
}
function Kill {
  sudo kill "$@" && sleep 1 && (sudo kill -9 "$@" || true)
}

Info "Testing sudo access"
sudo cat /dev/null
Info "Installing tcpreplay"
sudo apt-get install -y tcpreplay

Info "Building Rust workspace"
make -C "$REPO_ROOT" build

cat > $CONFIG << EOF
[
  {
      "SocketName": "$SOCKET"
    , "Interface": "$DUMMY"
    , "BlockSize": 1048576
    , "NumBlocks": 16
    , "BlockTimeoutMillis": 1000
    , "FanoutSize": 1
    , "User": "$(whoami)"
    , "Filter": "host 169.254.1.1 and host 169.254.1.2"
  }
]
EOF

Info "Setting up $DUMMY interface"
sudo /sbin/modprobe dummy
sudo ip link add $DUMMY type dummy || Error "$DUMMY may already exist"
sudo ifconfig $DUMMY promisc up

Info "Starting testimonyd"
sudo "$RUST_BIN/testimonyd" --config="$CONFIG" 2>&1 &
DAEMON_PID="$!"
sleep 1
sudo kill -0 $DAEMON_PID || Die "Daemon not running"

Info "Starting clients"
CLIENT_PIDS=""
for i in {1..10}; do
  "$RUST_BIN/testclient" --socket=$SOCKET --dump --count=10 >$DIR/out$i 2>$DIR/err$i &
  CLIENT_PIDS="$CLIENT_PIDS $!"
done
sleep 1
sudo kill -0 $CLIENT_PIDS || Die "Client not running"

Info "Sending packets to $DUMMY"
sudo tcpreplay -i $DUMMY --topspeed test.pcap
sleep 2

Info "Turning off client"
Kill $CLIENT_PIDS || Info "Failed to stop client, expected"
Info "Turning off daemon (graceful: SIGTERM exercises shm cleanup path)"
sudo kill -TERM $DAEMON_PID || Error "Failed to SIGTERM daemon"
# Wait up to 5s for graceful exit before SIGKILLing.
for _ in {1..50}; do
  sudo kill -0 $DAEMON_PID 2>/dev/null || break
  sleep 0.1
done
sudo kill -0 $DAEMON_PID 2>/dev/null && Kill $DAEMON_PID

Info "Verifying socket file was unlinked on graceful shutdown"
if [ -e "$SOCKET" ]; then
  Error "socket $SOCKET still present after daemon exit (UnlinkOnDrop failed?)"
  exit 1
fi

Info "Testing client output"
for i in {1..10}; do
  diff -Naur $DIR/out$i test.expected || Die "Output from client $i failed, see $DIR/out$i and $DIR/err$i"
done
rm -rf $DIR
sudo ip link delete $DUMMY || Error "Failed to clean up dummy $DUMMY"
Info "SUCCESS"
exit 0
