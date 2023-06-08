#!/bin/bash
COMMENT=""
if [ ! -z "$1" ]
  then
    TIMEOUT=$1
else
    TIMEOUT=10
fi

if which zypper > /dev/null; then
    ZYPPER=true
else
    ZYPPER=false
    echo "changed=no comment='The system does not have zypper'"
fi

endTime=$(( $(date +%s) + $TIMEOUT ))

if [ "$ZYPPER" = true ]
then
    output=$(timeout -v -s SIGKILL $TIMEOUT zypper -q refresh 2>&1 >/dev/null)
    if [ -z "$output" ] && [ $? = 0 ]
    then
	COMMENT="All is good. zypper ref successful."
        echo "changed=yes comment='${COMMENT}'"
        exit 0
    else
        COMMENT="ERROR: ${output} "
	#echo $COMMENT
        echo "changed=yes comment='${COMMENT}'"
        exit 1
    fi
fi
