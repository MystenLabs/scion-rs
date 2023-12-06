#!/bin/bash

VM_ADDRESS=$(multipass info scion | awk '/IPv4/{print $2}')
ssh ubuntu@$VM_ADDRESS << 'EOF'
    export PATH=/home/ubuntu/.local/bin/:$PATH
    cd scion
    ./scion.sh topology -c topology/tiny.topo
    ./scion.sh run
    EXTERNAL_ADDRESS=$(ip route get 9.9.9.9 | sed "s/.*src \([^ ]*\).*/\1/;t;d")
    DAEMON_ADDRESS_111=$(cat gen/sciond_addresses.json | jq -r ".\"1-ff00:0:111\"")
    sudo iptables -t nat -I PREROUTING \
        -d $EXTERNAL_ADDRESS -p tcp --match multiport --dports 30000:32000 \
        -j DNAT --to $DAEMON_ADDRESS_111
EOF
DAEMON_PORT=$(ssh ubuntu@$VM_ADDRESS 'cd scion; ./scion.sh sciond-addr 111 | cut -d ":" -f 2')
export SCION_DISPATCHER_PATH=/tmp/dispatcher.sock
export SCION_DAEMON_ADDRESS="[$VM_ADDRESS]:$DAEMON_PORT"
rm -f $SCION_DISPATCHER_PATH
ssh ubuntu@$VM_ADDRESS -fN -L $SCION_DISPATCHER_PATH:/run/shm/dispatcher/default.sock
