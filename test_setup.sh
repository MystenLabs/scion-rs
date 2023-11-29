#!/bin/bash

VM_ADDRESS=$(multipass info scion | awk '/IPv4/{print $2}')
DAEMON_PORT=$(ssh ubuntu@$VM_ADDRESS 'cd scion; ./scion.sh sciond-addr 111 | cut -d ":" -f 2')
export SCION_DISPATCHER_SOCKET=/tmp/dispatcher.sock
export DAEMON_ADDRESS="[$VM_ADDRESS]:$DAEMON_PORT"
rm $SCION_DISPATCHER_SOCKET
ssh ubuntu@$VM_ADDRESS -fN -L $SCION_DISPATCHER_SOCKET:/run/shm/dispatcher/default.sock
