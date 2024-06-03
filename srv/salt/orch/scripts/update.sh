#!/bin/bash
echo -e "Apply SLES updates using zypper update"
which zypper >&/dev/null
if [ ! $? -eq 0 ]
then
    echo "No zypper found."
    exit 1
fi

ZYPPER=$(which zypper)
XMLFILE=$(mktemp -t zypper_updates_XXXX)

delete_xmlfile () {
    rm -f $XMLFILE
}

which xmllint >&/dev/null
if [ ! $? -eq 0 ]
then
    echo "No xmllint found."
    delete_xmlfile
    exit 1
fi

XMLLINT=$(which xmllint)

timeout=60
interval=10
elapsed=0
FAILED=0

# Loop until zypper is not running or timeout is reached
while [ $timeout -ge $elapsed ]; do
    timeout -s9 10 $ZYPPER --no-refresh --no-gpg-checks --no-cd --non-interactive -x lu > $XMLFILE

    # Check if xml file is valid for further processing
    if [ ! $? -eq 0 ]
    then
	check_zypper_error=$("${XMLLINT}" --xpath "//message[@type='error']" $XMLFILE 2>/dev/null | grep "System management is locked")
	if [ ! -z "${check_zypper_error}" ]
	then
	    FAILED=1
	    echo -e "${check_zypper_error}"
	    #exit 1
	    echo "another zypper is running. Waiting for $interval seconds, Timeout is in $((timeout - elapsed)) seconds..."
	    sleep $interval
	    elapsed=$((elapsed + interval))
	else
	    echo "$ZYPPER -x lu failed with non 0 return code."
	    FAILED=2
	    break
	fi
    else
        break
    fi
done

if [ ! $FAILED -eq 0 ]
then
    echo "zypper command failed. Exit here."
    delete_xmlfile
    exit $FAILED
fi

# parse xml to get update package names
package_updates=$("${XMLLINT}" --xpath //update/@name $XMLFILE 2>/dev/null | awk -F '=' '{ print $2 }' | sed s/\"/\ /g | tr -d '\n')

if [ -z "${package_updates}" ]
then
    echo "no any packages to update found. exit."
    delete_xmlfile
    exit 0
fi

echo "apply updates for ${package_updates}"
$ZYPPER --non-interactive --quiet up --allow-name-change --allow-arch-change --allow-vendor-change $package_updates >&/dev/null &
#$ZYPPER lu >&/dev/null &
echo "Use this command to watch logs: tail -f /var/log/zypper.log"
delete_xmlfile
exit 0
