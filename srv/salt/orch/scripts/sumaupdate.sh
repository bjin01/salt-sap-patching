#!/bin/bash
MASTER=$(grep -r -E "^master:" /etc/venv-salt-minion/ | awk '{ print $2 }')
export no_proxy="localhost, 127.0.0.1, ${MASTER}"

PROXY=$(env | grep no_proxy)
echo $PROXY

echo -e "Apply SLES updates using zypper update"
which zypper >&/dev/null
if [ ! $? -eq 0 ]
then
    echo "No zypper found."
    exit 1
fi

which venv-salt-call >&/dev/null
if [ ! $? -eq 0 ]
then
    echo "No venv-salt-call found."
    exit 1
fi

minionid=$(cat /etc/venv-salt-minion/minion_id 2>/dev/null)
if [ -z "${minionid}" ]
then
    echo "No minion_id found. exit"
    exit 1
fi


SUMAJOBFILE=$(mktemp -t SUMA_UPDATE_XXXX)

delete_tempfile () {
    rm -f $SUMAJOBFILE
}

is_salt_minion_running() {
    systemctl is-active venv-salt-minion >&/dev/null
    if [ $? -ne 0 ]
    then
        return 1
    else
        return 0
    fi
}

jobid=0
schedule_suma_patch_job() {
    error1="not available"
    error2="failed"

    check_minion_running=$(is_salt_minion_running)
    #echo ${check_minion_running}
    if ! is_salt_minion_running
    then
        logger -s "venv-salt-minion is not running. exit."
        exit 1
    fi
    schedule_output=$(venv-salt-call publish.runner patch.patch arg="target_systems=${minionid}" 2>/dev/null)
    echo ${schedule_output}
    if [[ "${schedule_output}" =~ .*"${error1}".* ]] || [[ "${schedule_output}" =~ .*"${error2}".* ]]; then
        return 1
    fi
    echo -n "Jobid: "
    jobid=$(echo ${schedule_output} | grep -o -E "JobID:.*[0-9]+" | awk -F ":" '{ print $2 }' | tr -d [:space:]) 
    echo ${jobid} > ${SUMAJOBFILE}
    cat ${SUMAJOBFILE}
    return 0
}

schedule_suma_reboot_job() {
    check_minion_running=$(is_salt_minion_running)
    if ! is_salt_minion_running
    then
        logger "venv-salt-minion is not running. exit."
        exit 1
    fi
    schedule_output=$(venv-salt-call publish.runner patch.reboot arg="target_systems=${minionid}" 2>/dev/null)
    echo -n "Jobid: "
    jobid=$(echo ${schedule_output} | grep -o -E "JobID:.*[0-9]+" | awk -F ":" '{ print $2 }' | tr -d [:space:])
    echo ${jobid} > ${SUMAJOBFILE}
    cat ${SUMAJOBFILE}
    return 0
}

timeout=1200
interval=60
elapsed=0
FAILED=0

loop_check_job_status() {
    while  [ $timeout -ge $elapsed ]; do
        jobstatus=$(venv-salt-call publish.runner sumajob.status arg="${minionid}, ${jobid}" | awk -F ':' '{ print $2 }' | sed s/\ //g | tr -d '\n')
        echo ${minionid} job ${jobid} is ${jobstatus}
        case ${jobstatus} in
            Completed)
                return 0
                ;;
            Failed)
                return 1
                ;;
            Queued)
                echo "pause for $interval seconds and continue check until timeout or job failed or completed."
                ;;
            PickedUp)
                echo "pause for $interval seconds and continue check until timeout or job failed or completed."
                ;;
            *)
                echo -n "Job status check failed. Exit."
                return 1
                ;;
        esac
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    return 1
}

#schedule_suma_patch_job
if ! schedule_suma_patch_job
then
    logger -s "schedule_suma_patch_job failed."
    exit 1
fi

if [ "${jobid}" -eq 0 ]
then
    logger "No suma patch job scheduled. jobid is 0. Exit."
    exit 1
else
    loop_check_job_status
    schedule_suma_reboot_job
fi

delete_tempfile
exit 0