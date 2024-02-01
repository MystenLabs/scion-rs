#!/bin/bash
#
# This script assumes you have set up multipass as described in CONTRIBUTING.md
# and the SCION VM is running.
#
# Usage: . ./test_setup.sh

VM_ADDRESS=$(multipass info scion | awk '/IPv4/{print $2}')

export SCION_DISPATCHER_PATH=/tmp/dispatcher.sock
export SCION_DAEMON_ADDRESS="[$VM_ADDRESS]:30255"

rm -f $SCION_DISPATCHER_PATH
ssh -i multipass/test_id_ed25519 ubuntu@$VM_ADDRESS -fN -L \
    $SCION_DISPATCHER_PATH:/run/shm/dispatcher/default.sock
