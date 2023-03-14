# __salt runner module - sumapatch__

sumapatch is a salt runner module that uses SUSE Manager / [Uyuni](https://www.uyuni-project.org/) API to schedule patch jobs. 

## __Features included within the module:__
* schedule patch jobs based on groups defined in SUSE Manager
* allows setting delay time for job start 
* online presence check - if the mininons are online via salt-run manage.up check
* writes logs to specified log files
* hand over scheduled job IDs to [jobchecking](../../jobchecker/jobchecker.md) for job status monitoring
* no_patch - grains key to be used as exceptional system lock to not patch it within groups
* Use encrypted SUMA API login password in configuration file 

Here is a sample salt orchestrator sls file (salt://orch/test1.sls) to use sumapatch module:
<details><summary>test1.sls</summary>

```
run_patching:
  salt.runner:
    - name: sumapatch.patch 
    - groups:
      - testgrp
      - othergroup
    - kwargs:
      delay: 5
      logfile: /var/log/patching/sumapatching.log
      timeout: 2
      gather_job_timeout: 8
      jobchecker_timeout: 20
      jobchecker_emails:
        - admin@mycorp.com
        - admin2@others.com
      grains: 
        no_patch: False
```

</details>

## Explain kwargs:
The supported kwargs are:
- delay: the number given is in minutes. The delay time will be added to the current time to scheduled patch jobs.
- logfile: if defined the logs will be written to the specified log file. But the logfile and directory must belong to user salt and created before using it
- timeout: given number in seconds. This is used for minion presence check for salt-run manage.up 
- gather_job_timeout: given number in seconds. [manage.up](https://docs.saltproject.io/en/latest/ref/runners/all/salt.runners.manage.html#salt.runners.manage.up)
- jobchecker_timeout: given number in minutes. It tells jobchecker how long to monitor the jobs
- jobchecker_emails: email addresses where the final job monitoring results will be sent to.
- no_patch: is the grains key name. If the value is True then the respective minion will be excluded from patching.

## Configuration and preparations:

The sumaptch module uses the a configuration file. (Example: [/etc/salt/master.d/spacewalk.conf](../etc/salt/master.d/spacewalk.conf))

### __Create configuration file for SUSE Manager API:__

**Password encryption**:
The module sumpatch supports using encrypted password in the configuration file.
Therefore use the [encrypt.py](../encrypt.py) to generat a encrypted password:
```
python3.6 encrypt.py <YOUR-SUMA-API-PASSWORD>
```
The output of encrypt.py gives the encrypted password and the key will be needed for decryption.
The encrypted password must be provided in the configuration file and stored in ```/etc/salt/master.d```
For example:
```
suma_api:
  suma1.bo2go.home:
    username: 'admin'
    password: gAAAAABj_xzeu23IpzKM-mYOYOS1HwV3leuntobtovVru5TvK0pdJVJjvStXPSO3IOOCTfBSoIQZHE_GhoCokaaj0tAOdyzcvQ==
```
Do not forget to restart salt-master after changing or adding configurations on salt master. \
```systemctl restart salt-master```

**Additionally you must set an OS environment variable SUMAKEY**
```
export SUMAKEY=R2bfp223Qsk-pX970Jw8tyJUChT4-e2J8anZ4G4n4IM=
```
The SUMAKEY will be needed by the salt-runner module which uses it for password decryption. \
**If the SUMAKEY is not found then the script will use the value of password in [sumaconfig](../etc/salt/master.d/spacewalk.conf) as clear text password.**

## __Installation steps (run as root or with sudo):__
```
git clone https://github.com/bjin01/salt-sap-patching.git
cd salt-sap-patching
mkdir /var/log/patching/
touch /var/log/patching/patching.log
chown salt. /var/log/patching/patching.log
cp srv/salt/_runners/sumapatch.py /usr/share/susemanager/modules/runners/
salt-run saltutil.sync_runners
```

## __Execute the orchestrator:__
```salt-run state.orch orch.test1```

## __Logs:__
Upon logfile defined in the sls file there is one default log file: \
```/var/log/patching/patching.log```
And the logfile specified in the sls of above example: \
```/var/log/patching/sumapatching.log``` 

Logfiles and directories must have ownership belonging to user salt. \
Use below commands to create directory and log files and set correct ownerships: \
Run as root user or with sudo (if not already done in installation steps):
```
mkdir -p /var/log/patching
touch /var/log/patching/patching.log
touch /var/log/patching/sumapatching.log
chown -R salt. /var/log/patching/
```
