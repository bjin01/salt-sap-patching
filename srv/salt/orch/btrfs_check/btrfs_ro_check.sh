#!/bin/bash
if which btrfs > /dev/null; then
    #echo "btrfs command exists."
    BTRFS=true
else
    BTRFS=false
    echo "changed=no comment='The system does not have btrfs filesystem'"
fi

READONLY=false
COMMENT="readonly: "

if [ "$BTRFS" = true ]
then
    for i in $(mount | grep btrfs | awk '{ print $3 }')
    do 
        output=$(btrfs property get -ts $i)
        if [[ $output = *ro=true* ]]
        then
           #echo ${i}=readonly
           READONLY=true
           COMMENT+="${i} " 
        fi
    done
fi

if [ "$READONLY" = true ]
then
    echo "changed=yes comment="${COMMENT}" "
    if which venv-salt-minion > /dev/null; then
        venv-salt-call event.send 'btrfs/readonly/found' '{btrfs_ro: '"'$COMMENT'"'}'
    else
        salt-call event.send 'btrfs/readonly/found' '{btrfs_ro: '"'$COMMENT'"'}'
    fi
else
    echo "changed=no comment='all is good. no readonly btrfs found.'"
fi

